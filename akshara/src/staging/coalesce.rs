use super::StagedOperation;
use std::collections::BTreeMap;

/// Coalesce operations by path.
///
/// Later operations to the same path override earlier ones.
pub fn coalesce_operations(operations: Vec<StagedOperation>) -> Vec<StagedOperation> {
    let mut by_path: BTreeMap<String, StagedOperation> = BTreeMap::new();

    for op in operations {
        let path = op.path().to_string();

        match op {
            StagedOperation::Insert { .. }
            | StagedOperation::Update { .. }
            | StagedOperation::Link { .. } => {
                // Insert/Update/Link replaces any prior operation at same path
                by_path.insert(path, op);
            }
            StagedOperation::Delete { .. } => {
                // Delete clears any prior operations at same path
                by_path.insert(path, op);
            }
        }
    }

    by_path.into_values().collect()
}
