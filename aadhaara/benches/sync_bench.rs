use akshara_aadhaara::{
    Address, Block, Delta, GraphKey, GraphStore, InMemoryStore, Reconciler, SecretIdentity,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::rngs::OsRng;
use tokio::runtime::Runtime;

fn bench_fulfillment(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let key = GraphKey::generate(&mut rng);
    let store = InMemoryStore::new();

    // 1. Pre-fill the store with 1000 blocks
    let mut addresses = Vec::new();
    let gid = akshara_aadhaara::GraphId::new();
    rt.block_on(async {
        for i in 0..1000 {
            let data = vec![i as u8; 1024]; // 1KB blocks
            let block = Block::new(gid, data, "test".into(), vec![], &key, &identity).unwrap();
            let addr = Address::from(block.id());
            store.put_block(&block).await.unwrap();
            addresses.push(addr);
        }
    });

    let delta = Delta::new(addresses);
    let reconciler = Reconciler::new(&store, identity.public().signing_key().clone());

    let mut group = c.benchmark_group("protocol");
    group.throughput(Throughput::Elements(1000));

    group.bench_function(BenchmarkId::new("fulfill", 1000), |b| {
        b.iter(|| {
            rt.block_on(async {
                // Now we await the full fulfillment
                let portions = reconciler.fulfill(&delta).await.unwrap();
                assert_eq!(portions.len(), 1000);
            });
        });
    });

    group.finish();
}

criterion_group!(benches, bench_fulfillment);
criterion_main!(benches);
