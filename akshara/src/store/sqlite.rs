use akshara_aadhaara::{AksharaError, BlockId, GraphId, GraphStore, ManifestId, StoreError};
use async_trait::async_trait;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// A persistent storage backend backed by SQLite.
#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Opens a connection to a SQLite database on disk.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AksharaError> {
        let conn = Connection::open(path).map_err(|e| {
            AksharaError::Store(StoreError::IoError(format!("SQLite open error: {}", e)))
        })?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_tables()?;
        Ok(store)
    }

    /// Opens an in-memory SQLite database connection (useful for testing).
    pub fn in_memory() -> Result<Self, AksharaError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            AksharaError::Store(StoreError::IoError(format!(
                "SQLite in_memory open error: {}",
                e
            )))
        })?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<(), AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS blocks (
                 block_id BLOB PRIMARY KEY,
                 data BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS manifests (
                 manifest_id BLOB PRIMARY KEY,
                 graph_id BLOB NOT NULL,
                 data BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS graph_heads (
                 graph_id BLOB,
                 manifest_id BLOB,
                 PRIMARY KEY (graph_id, manifest_id)
             );

             CREATE TABLE IF NOT EXISTS lockboxes (
                 lakshana BLOB NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_lockboxes_lakshana ON lockboxes(lakshana);

             CREATE TABLE IF NOT EXISTS prekey_bundles (
                 device_key BLOB PRIMARY KEY,
                 data BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS one_time_prekeys (
                 device_key BLOB NOT NULL,
                 prekey_index INTEGER NOT NULL,
                 data BLOB NOT NULL,
                 PRIMARY KEY (device_key, prekey_index),
                 FOREIGN KEY (device_key) REFERENCES prekey_bundles(device_key) ON DELETE CASCADE
             );",
        )
        .map_err(|e| {
            AksharaError::Store(StoreError::IoError(format!(
                "SQLite table init error: {}",
                e
            )))
        })?;

        Ok(())
    }
}

#[async_trait]
impl GraphStore for SqliteStore {
    async fn put_block_bytes(&self, id: &BlockId, data: &[u8]) -> Result<(), AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        conn.execute(
            "INSERT OR IGNORE INTO blocks (block_id, data) VALUES (?1, ?2)",
            (id.to_bytes(), data),
        )
        .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        Ok(())
    }

    async fn get_block_bytes(&self, id: &BlockId) -> Result<Option<Vec<u8>>, AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let mut stmt = conn
            .prepare("SELECT data FROM blocks WHERE block_id = ?1")
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        let mut rows = stmt
            .query((id.to_bytes(),))
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
        {
            let data: Vec<u8> = row
                .get(0)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn put_manifest_bytes(
        &self,
        id: &ManifestId,
        graph_id: &GraphId,
        parents: &[ManifestId],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let tx = conn
            .transaction()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        // 1. Insert manifest metadata
        tx.execute(
            "INSERT OR IGNORE INTO manifests (manifest_id, graph_id, data) VALUES (?1, ?2, ?3)",
            (id.to_bytes(), graph_id.as_bytes().as_ref(), data),
        )
        .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        // 2. Remove parent manifest IDs from heads list
        for parent in parents {
            tx.execute(
                "DELETE FROM graph_heads WHERE graph_id = ?1 AND manifest_id = ?2",
                (graph_id.as_bytes().as_ref(), parent.to_bytes()),
            )
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        }

        // 3. Insert the new manifest as a current head
        tx.execute(
            "INSERT OR IGNORE INTO graph_heads (graph_id, manifest_id) VALUES (?1, ?2)",
            (graph_id.as_bytes().as_ref(), id.to_bytes()),
        )
        .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        tx.commit()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        Ok(())
    }

    async fn get_manifest_bytes(&self, id: &ManifestId) -> Result<Option<Vec<u8>>, AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let mut stmt = conn
            .prepare("SELECT data FROM manifests WHERE manifest_id = ?1")
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        let mut rows = stmt
            .query((id.to_bytes(),))
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
        {
            let data: Vec<u8> = row
                .get(0)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn get_heads(&self, graph_id: &GraphId) -> Result<Vec<ManifestId>, AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let mut stmt = conn
            .prepare("SELECT manifest_id FROM graph_heads WHERE graph_id = ?1")
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        let mut rows = stmt
            .query((graph_id.as_bytes().as_ref(),))
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        let mut heads = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
        {
            let bytes: Vec<u8> = row
                .get(0)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            let manifest_id = ManifestId::try_from(bytes.as_slice())?;
            heads.push(manifest_id);
        }
        Ok(heads)
    }

    async fn put_lockbox_bytes(&self, lakshana: &[u8], data: &[u8]) -> Result<(), AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        conn.execute(
            "INSERT INTO lockboxes (lakshana, data) VALUES (?1, ?2)",
            (lakshana, data),
        )
        .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        Ok(())
    }

    async fn get_lockboxes_bytes(&self, lakshana: &[u8]) -> Result<Vec<Vec<u8>>, AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let mut stmt = conn
            .prepare("SELECT data FROM lockboxes WHERE lakshana = ?1")
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        let mut rows = stmt
            .query((lakshana,))
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        let mut lockboxes = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
        {
            let data: Vec<u8> = row
                .get(0)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            lockboxes.push(data);
        }
        Ok(lockboxes)
    }

    async fn put_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
        data: &[u8],
    ) -> Result<(), AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        conn.execute(
            "INSERT OR REPLACE INTO prekey_bundles (device_key, data) VALUES (?1, ?2)",
            (device_key, data),
        )
        .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        Ok(())
    }

    async fn get_prekey_bundle_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let mut stmt = conn
            .prepare("SELECT data FROM prekey_bundles WHERE device_key = ?1")
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        let mut rows = stmt
            .query((device_key,))
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
        {
            let data: Vec<u8> = row
                .get(0)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn put_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
        prekeys: &[(u32, &[u8])],
    ) -> Result<(), AksharaError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let tx = conn
            .transaction()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        for (index, data) in prekeys {
            tx.execute(
                "INSERT OR REPLACE INTO one_time_prekeys (device_key, prekey_index, data) VALUES (?1, ?2, ?3)",
                (device_key, index, data),
            ).map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        }

        tx.commit()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        Ok(())
    }

    async fn get_one_time_prekeys_bytes(
        &self,
        device_key: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>, AksharaError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let mut stmt = conn
            .prepare("SELECT prekey_index, data FROM one_time_prekeys WHERE device_key = ?1")
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
        let mut rows = stmt
            .query((device_key,))
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        let mut prekeys = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
        {
            let index: u32 = row
                .get(0)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            let data: Vec<u8> = row
                .get(1)
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            prekeys.push((index, data));
        }
        Ok(prekeys)
    }

    async fn consume_one_time_prekey_bytes(
        &self,
        device_key: &[u8],
        prekey_index: u32,
    ) -> Result<Option<Vec<u8>>, AksharaError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| AksharaError::Store(StoreError::LockPoisoned))?;
        let tx = conn
            .transaction()
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

        let key_bytes_opt = {
            let mut stmt = tx
                .prepare(
                    "SELECT data FROM one_time_prekeys WHERE device_key = ?1 AND prekey_index = ?2",
                )
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            let mut rows = stmt
                .query((device_key, prekey_index))
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

            if let Some(row) = rows
                .next()
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?
            {
                let data: Vec<u8> = row
                    .get(0)
                    .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
                Some(data)
            } else {
                None
            }
        };

        if let Some(data) = key_bytes_opt {
            tx.execute(
                "DELETE FROM one_time_prekeys WHERE device_key = ?1 AND prekey_index = ?2",
                (device_key, prekey_index),
            )
            .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;

            tx.commit()
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            Ok(Some(data))
        } else {
            tx.rollback()
                .map_err(|e| AksharaError::Store(StoreError::IoError(e.to_string())))?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use akshara_aadhaara::{BlockId, GraphId, Lakshana, ManifestId};

    fn create_dummy_block_id() -> BlockId {
        BlockId::from_sha256(&[0xaa; 32])
    }

    fn create_dummy_manifest_id() -> ManifestId {
        ManifestId::from_sha256(&[0xbb; 32])
    }

    #[tokio::test]
    async fn test_sqlite_block_roundtrip() {
        let store = SqliteStore::in_memory().unwrap();
        let id = create_dummy_block_id();
        let data = b"hello block content";

        store.put_block_bytes(&id, data).await.unwrap();
        let retrieved = store.get_block_bytes(&id).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        let missing = store
            .get_block_bytes(&BlockId::from_sha256(&[0xcc; 32]))
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_manifest_and_heads() {
        let store = SqliteStore::in_memory().unwrap();
        let graph_id = GraphId::new();

        let m1 = create_dummy_manifest_id();
        let m2 = ManifestId::from_sha256(&[0x22; 32]);
        let m3 = ManifestId::from_sha256(&[0x33; 32]);

        let data = b"dummy manifest data";

        // 1. Store m1 (no parents) -> heads = [m1]
        store
            .put_manifest_bytes(&m1, &graph_id, &[], data)
            .await
            .unwrap();
        let heads = store.get_heads(&graph_id).await.unwrap();
        assert_eq!(heads, vec![m1]);

        // 2. Store m2 (parent m1) -> heads = [m2]
        store
            .put_manifest_bytes(&m2, &graph_id, &[m1], data)
            .await
            .unwrap();
        let heads = store.get_heads(&graph_id).await.unwrap();
        assert_eq!(heads, vec![m2]);

        // 3. Store m3 (parent m2) -> heads = [m3]
        store
            .put_manifest_bytes(&m3, &graph_id, &[m2], data)
            .await
            .unwrap();
        let heads = store.get_heads(&graph_id).await.unwrap();
        assert_eq!(heads, vec![m3]);
    }

    #[tokio::test]
    async fn test_sqlite_lockbox_isolation() {
        let store = SqliteStore::in_memory().unwrap();
        let lak1 = Lakshana::new([0x01; 32]);
        let lak2 = Lakshana::new([0x02; 32]);

        store
            .put_lockbox_bytes(lak1.as_bytes().as_ref(), b"box 1")
            .await
            .unwrap();
        store
            .put_lockbox_bytes(lak1.as_bytes().as_ref(), b"box 2")
            .await
            .unwrap();
        store
            .put_lockbox_bytes(lak2.as_bytes().as_ref(), b"box 3")
            .await
            .unwrap();

        let boxes1 = store
            .get_lockboxes_bytes(lak1.as_bytes().as_ref())
            .await
            .unwrap();
        assert_eq!(boxes1, vec![b"box 1".to_vec(), b"box 2".to_vec()]);

        let boxes2 = store
            .get_lockboxes_bytes(lak2.as_bytes().as_ref())
            .await
            .unwrap();
        assert_eq!(boxes2, vec![b"box 3".to_vec()]);
    }

    #[tokio::test]
    async fn test_sqlite_prekey_bundle_roundtrip_and_consumption() {
        let store = SqliteStore::in_memory().unwrap();

        let mnemonic = akshara_aadhaara::SecretIdentity::generate_mnemonic().unwrap();
        let master = akshara_aadhaara::MasterIdentity::from_mnemonic(&mnemonic, "").unwrap();
        let bundle = master.generate_pre_key_bundle(0, 0, 5).unwrap();
        let device_key = bundle.device_identity.signing_key().clone();

        // Check put/get bundle via the high-level GraphStore methods (testing serialization mapping)
        store.put_prekey_bundle(&bundle).await.unwrap();
        let retrieved = store.get_prekey_bundle(&device_key).await.unwrap().unwrap();
        assert_eq!(retrieved.pre_keys.len(), 5);

        // Consume index 2
        let key_2 = store.consume_prekey(&device_key, 2).await.unwrap();
        assert!(key_2.is_some());

        // Consume index 2 again -> should return None (one-time use check)
        let key_2_again = store.consume_prekey(&device_key, 2).await.unwrap();
        assert!(key_2_again.is_none());

        // Verify the rest of the bundle is intact but index 2 is gone
        let final_bundle = store.get_prekey_bundle(&device_key).await.unwrap().unwrap();
        assert_eq!(final_bundle.pre_keys.len(), 4);
        assert!(!final_bundle.pre_keys.contains_key(&2));
        assert!(final_bundle.pre_keys.contains_key(&0));
    }
}
