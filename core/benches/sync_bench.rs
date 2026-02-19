use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::rngs::OsRng;
use sovereign_core::{
    Address, Block, Delta, GraphKey, GraphStore, InMemoryStore, Reconciler, SecretIdentity,
};

fn bench_fulfillment(c: &mut Criterion) {
    let mut rng = OsRng;
    let identity = SecretIdentity::generate(&mut rng);
    let key = GraphKey::generate(&mut rng);
    let mut store = InMemoryStore::new();

    // 1. Pre-fill the store with 1000 blocks
    let mut addresses = Vec::new();
    for i in 0..1000 {
        let data = vec![i as u8; 1024]; // 1KB blocks
        let block = Block::new(data, "test".into(), vec![], &key, &identity).unwrap();
        let addr = Address::from(block.id());
        store.put_block(&block).unwrap();
        addresses.push(addr);
    }

    let delta = Delta::new(addresses);
    let reconciler = Reconciler::new(&store, identity.public().signing_key().clone());

    let mut group = c.benchmark_group("protocol");
    group.throughput(Throughput::Elements(1000));

    group.bench_function(BenchmarkId::new("fulfill", 1000), |b| {
        b.iter(|| {
            // We iterate through the fulfillment iterator
            for portion_res in reconciler.fulfill(&delta) {
                let _ = portion_res.unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_fulfillment);
criterion_main!(benches);
