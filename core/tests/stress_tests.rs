use rand::Rng;
use rand::rngs::OsRng;
use sovereign_core::{
    Address, Block, GraphKey, GraphStore, GraphWalker, InMemoryStore, SecretIdentity,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;

#[test]
#[ignore]
fn test_byzantine_bit_flip_fuzzer() {
    let mut rng = OsRng;
    let master = SecretIdentity::generate(&mut rng);
    let key = GraphKey::generate(&mut rng);

    let data = b"Target Truth".to_vec();
    let block = Block::new(data, "post".into(), vec![], &key, &master).unwrap();
    let block_bytes = serde_cbor::to_vec(&block).unwrap();

    for _ in 0..100 {
        let mut fuzzed_bytes = block_bytes.clone();
        let bit_to_flip = rng.gen_range(0..fuzzed_bytes.len());
        fuzzed_bytes[bit_to_flip] ^= 0x01;

        let res: Result<Block, _> = serde_cbor::from_slice(&fuzzed_bytes);

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
    let graph_id = sovereign_core::GraphId::new();
    let root = sovereign_core::BlockId::from_sha256(&[0xFF; 32]);
    let anchor = sovereign_core::ManifestId::from_sha256(&[0u8; 32]);

    let manifest = sovereign_core::Manifest::new(graph_id, root, vec![], anchor, &master);
    let manifest_bytes = serde_cbor::to_vec(&manifest).unwrap();

    for _ in 0..100 {
        let mut fuzzed_bytes = manifest_bytes.clone();
        let bit_to_flip = rng.gen_range(0..fuzzed_bytes.len());
        fuzzed_bytes[bit_to_flip] ^= 0x01;

        let res: Result<sovereign_core::Manifest, _> = serde_cbor::from_slice(&fuzzed_bytes);

        if let Ok(fuzzed_manifest) = res {
            let audit_res = fuzzed_manifest.verify_integrity();
            assert!(audit_res.is_err());
        }
    }
}

#[test]
#[ignore]
fn test_byzantine_walker_robustness() {
    let mut rng = OsRng;
    let mut store = InMemoryStore::new();
    let master = SecretIdentity::generate(&mut rng);
    let key = GraphKey::generate(&mut rng);

    let leaf = Block::new(b"leaf".to_vec(), "data".into(), vec![], &key, &master).unwrap();
    store.put_block(&leaf).unwrap();

    let mut root_map = BTreeMap::new();
    root_map.insert("file".to_string(), Address::from(leaf.id()));
    let root_block = Block::new(
        serde_cbor::to_vec(&root_map).unwrap(),
        "index".into(),
        vec![],
        &key,
        &master,
    )
    .unwrap();
    store.put_block(&root_block).unwrap();

    for _ in 0..50 {
        let mut corrupt_bytes = serde_cbor::to_vec(&leaf).unwrap();
        let pos = rng.gen_range(0..corrupt_bytes.len());
        corrupt_bytes[pos] ^= 0xFF;

        if let Ok(corrupt_block) = serde_cbor::from_slice::<Block>(&corrupt_bytes) {
            store.put_block(&corrupt_block).unwrap();
        }

        {
            let walker = GraphWalker::new(&store, master.public().signing_key().clone());
            let _ = walker.resolve_path(root_block.id(), "file", &key);
        }
    }
}

#[test]
#[ignore]
fn store_rwlock_torture_test() {
    let store = Arc::new(Mutex::new(InMemoryStore::new()));
    let mut threads = vec![];

    for i in 0..10 {
        let store_ref = Arc::clone(&store);
        let t = thread::spawn(move || {
            let mut rng = OsRng;
            let identity = SecretIdentity::generate(&mut rng);
            let key = GraphKey::generate(&mut rng);

            for j in 0..100 {
                let data = format!("thread-{}-entry-{}", i, j);
                let block =
                    Block::new(data.into_bytes(), "test".into(), vec![], &key, &identity).unwrap();
                let id = block.id();

                {
                    let mut lock = store_ref.lock().unwrap();
                    lock.put_block(&block).unwrap();
                }

                {
                    let lock = store_ref.lock().unwrap();
                    let retrieved = lock.get_block(&id).unwrap().unwrap();
                    assert_eq!(retrieved.id(), id);
                }
            }
        });
        threads.push(t);
    }

    for t in threads {
        t.join().unwrap();
    }
}
