use akshara_aadhaara::{
    Address, Block, GraphKey, GraphStore, GraphWalker, InMemoryStore, SecretIdentity,
};
use rand::Rng;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
#[ignore]
fn test_byzantine_bit_flip_fuzzer() {
    let mut rng = OsRng;
    let master = SecretIdentity::generate(&mut rng);
    let key = GraphKey::generate(&mut rng);

    let data = b"Target Truth".to_vec();
    let block = Block::new(data, "post".into(), vec![], &key, &master).unwrap();
    let block_bytes = serde_ipld_dagcbor::to_vec(&block).unwrap();

    for _ in 0..100 {
        let mut fuzzed_bytes = block_bytes.clone();
        let bit_to_flip = rng.gen_range(0..fuzzed_bytes.len());
        fuzzed_bytes[bit_to_flip] ^= 0x01;

        let res: Result<Block, _> = serde_ipld_dagcbor::from_slice(&fuzzed_bytes);

        if let Ok(fuzzed_block) = res {
            let audit_res = fuzzed_block.verify_integrity();
            assert!(audit_res.is_err());
        }
    }
}

#[test]
#[ignore]
fn test_byzantine_manifest_corruption() {
    let mut rng = OsRng;
    let master = SecretIdentity::generate(&mut rng);
    let graph_id = akshara_aadhaara::GraphId::new();
    let root = akshara_aadhaara::BlockId::from_sha256(&[0xFF; 32]);
    let anchor = akshara_aadhaara::ManifestId::from_sha256(&[0u8; 32]);

    let manifest = akshara_aadhaara::Manifest::new(graph_id, root, vec![], anchor, &master);
    let manifest_bytes = serde_ipld_dagcbor::to_vec(&manifest).unwrap();

    for _ in 0..100 {
        let mut fuzzed_bytes = manifest_bytes.clone();
        let bit_to_flip = rng.gen_range(0..fuzzed_bytes.len());
        fuzzed_bytes[bit_to_flip] ^= 0x01;

        let res: Result<akshara_aadhaara::Manifest, _> =
            serde_ipld_dagcbor::from_slice(&fuzzed_bytes);

        if let Ok(fuzzed_manifest) = res {
            let audit_res = fuzzed_manifest.verify_integrity();

            // If the audit passed, it must be because the internal data is actually
            // identical to the original (i.e., the bit flip was encoding noise
            // ignored by the decoder).
            if audit_res.is_ok() {
                assert_eq!(
                    fuzzed_manifest.id(),
                    manifest.id(),
                    "Audit passed despite ID change! Critical integrity failure at bit {}",
                    bit_to_flip
                );
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_byzantine_walker_robustness() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let master = SecretIdentity::generate(&mut rng);
    let key = GraphKey::generate(&mut rng);

    let leaf = Block::new(b"leaf".to_vec(), "data".into(), vec![], &key, &master).unwrap();
    store.put_block(&leaf).await.unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("file".to_string(), Address::from(leaf.id()));
    let root_bytes = serde_ipld_dagcbor::to_vec(&root_map).unwrap();

    let root_block =
        Block::new(root_bytes, "akshara.index.v1".into(), vec![], &key, &master).unwrap();
    store.put_block(&root_block).await.unwrap();

    for _ in 0..50 {
        let leaf_bytes = serde_ipld_dagcbor::to_vec(&leaf).unwrap();
        let mut corrupt_bytes = leaf_bytes.clone();
        let pos = rng.gen_range(0..corrupt_bytes.len());
        corrupt_bytes[pos] ^= 0xFF;

        if let Ok(corrupt_block) = serde_ipld_dagcbor::from_slice::<Block>(&corrupt_bytes) {
            store.put_block(&corrupt_block).await.unwrap();
        }

        {
            let walker = GraphWalker::new(&store, master.public().signing_key().clone());
            let _ = walker.resolve_path(root_block.id(), "file", &key).await;
        }
    }
}

#[tokio::test]
#[ignore]
async fn store_rwlock_torture_test() {
    let store = Arc::new(InMemoryStore::new());
    let mut handles = vec![];

    for i in 0..10 {
        let store_ref = Arc::clone(&store);
        let h = tokio::spawn(async move {
            let mut rng = OsRng;
            let identity = SecretIdentity::generate(&mut rng);
            let key = GraphKey::generate(&mut rng);

            for j in 0..100 {
                let data = format!("thread-{}-entry-{}", i, j);
                let block =
                    Block::new(data.into_bytes(), "test".into(), vec![], &key, &identity).unwrap();
                let id = block.id();

                {
                    // No need for Mutex here as InMemoryStore is thread-safe internally
                    let mut store_mut = (*store_ref).clone();
                    store_mut.put_block(&block).await.unwrap();
                }

                {
                    let retrieved = store_ref.get_block(&id).await.unwrap().unwrap();
                    assert_eq!(retrieved.id(), id);
                }
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
#[ignore]
async fn test_async_storm_manifest_heads() {
    let store = Arc::new(tokio::sync::RwLock::new(InMemoryStore::new()));
    let graph_id = akshara_aadhaara::GraphId::new();
    let root = akshara_aadhaara::BlockId::from_sha256(&[0xAA; 32]);
    let anchor = akshara_aadhaara::ManifestId::from_sha256(&[0x00; 32]);

    let mut handles = vec![];

    // Spawn 50 tasks trying to update heads simultaneously
    for _ in 0..50 {
        let store_ref = Arc::clone(&store);
        let mnemonic = SecretIdentity::generate_mnemonic().unwrap();
        let identity_ref = SecretIdentity::from_mnemonic(&mnemonic, "pass").unwrap();

        let h = tokio::spawn(async move {
            for _ in 0..10 {
                // 1. Get current heads
                let heads = {
                    let s = store_ref.read().await;
                    s.get_heads(&graph_id).await.unwrap()
                };

                // 2. Create new manifest pointing to current heads
                let m =
                    akshara_aadhaara::Manifest::new(graph_id, root, heads, anchor, &identity_ref);

                // 3. Put manifest
                {
                    let mut s = store_ref.write().await;
                    s.put_manifest(&m).await.unwrap();
                }
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.await.unwrap();
    }

    // FINAL VERIFICATION:
    // The heads must be convergent. Since every manifest points to previous heads,
    // we should ultimately end up with a small number of heads (likely 1 if sequential,
    // or few if highly concurrent).
    let s = store.read().await;
    let final_heads = s.get_heads(&graph_id).await.unwrap();
    assert!(
        !final_heads.is_empty(),
        "Heads should not be empty after storm"
    );
    assert!(
        final_heads.len() <= 50,
        "Heads count exploded - logic error in head pruning"
    );
}
