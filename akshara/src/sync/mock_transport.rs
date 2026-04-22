//! Mock transport for testing and demos.
//!
//! Simulates a peer with configurable behavior (delays, errors, etc.)
//! without requiring a real network connection.

use std::pin::Pin;
use std::time::Duration;

use akshara_aadhaara::{Delta, Heads, ManifestId, Portion};
use futures::stream::{self, Stream};
use tokio::time::sleep;

use super::transport::SyncTransport;
use crate::error::{Error, Result};

use std::sync::{Arc, RwLock};

/// Mock transport that simulates a peer for testing.
pub struct MockTransport {
    /// Simulated network delay
    pub delay_ms: u64,
    /// Probability of simulated failure
    pub failure_rate: f64,
    /// Recorded portions that were pushed to this transport
    pub pushed_portions: Arc<RwLock<Vec<Portion>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            delay_ms: 10,
            failure_rate: 0.0,
            pushed_portions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a new mock transport with custom delay.
    pub fn with_delay(delay_ms: u64) -> Self {
        Self {
            delay_ms,
            failure_rate: 0.0,
            pushed_portions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Simulate network delay.
    async fn simulate_delay(&self) {
        if self.delay_ms > 0 {
            sleep(Duration::from_millis(self.delay_ms)).await;
        }
    }

    /// Simulate random failures.
    fn simulate_failure(&self) -> Result<()> {
        if self.failure_rate > 0.0 && rand::random::<f64>() < self.failure_rate {
            Err(Error::SyncFailed("Simulated network failure".to_string()))
        } else {
            Ok(())
        }
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SyncTransport for MockTransport {
    async fn exchange_heads(
        &self,
        _graph_id: akshara_aadhaara::GraphId,
        _local_heads: Vec<ManifestId>,
    ) -> Result<Heads> {
        self.simulate_delay().await;
        self.simulate_failure()?;

        // Simulate peer with empty heads (fresh peer)
        // In a real implementation, this would query the relay/peer
        Ok(Heads::new(_graph_id, vec![]))
    }

    async fn request_portions(
        &self,
        _delta: &Delta,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Portion>> + Send>>> {
        self.simulate_delay().await;
        self.simulate_failure()?;

        // Return empty stream (no data to sync from mock peer)
        Ok(Box::pin(stream::empty()))
    }

    async fn push_portions(
        &self,
        mut portions: Pin<Box<dyn Stream<Item = Result<Portion>> + Send>>,
    ) -> Result<()> {
        self.simulate_delay().await;
        self.simulate_failure()?;

        use futures::StreamExt;
        while let Some(portion_result) = portions.next().await {
            let portion = portion_result?;
            let mut buffer = self
                .pushed_portions
                .write()
                .map_err(|_| Error::Internal("Lock poisoned".to_string()))?;
            buffer.push(portion);
        }

        Ok(())
    }
}
