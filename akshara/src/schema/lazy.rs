use akshara_aadhaara::Address;
use serde::{Deserialize, Serialize};

/// `LazyField` acts as a placeholder for document fields that are stored
/// in the graph but not yet fetched into memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LazyField<T> {
    /// The coordinate path where the data is located.
    path: String,
    /// The address of the block if it's already known, otherwise None.
    address: Option<Address>,
    #[serde(skip)]
    _marker: std::marker::PhantomData<T>,
}

impl<T> LazyField<T> {
    /// Creates a new lazy placeholder for the given path.
    pub fn new(path: String) -> Self {
        Self {
            path,
            address: None,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the coordinate path of the data.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the address of the data, if resolved.
    pub fn address(&self) -> Option<&Address> {
        self.address.as_ref()
    }

    /// Sets the resolved block address of this lazy field.
    pub fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }
}
