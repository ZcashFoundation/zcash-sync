use criterion::{criterion_group, criterion_main, Criterion};
use sync::{scan_all, NETWORK};
use tokio::runtime::Runtime;
use zcash_client_backend::encoding::decode_extended_full_viewing_key;
use zcash_primitives::consensus::Parameters;

fn scan(c: &mut Criterion) {
    dotenv::dotenv().unwrap();
    env_logger::init();

    let ivk = dotenv::var("IVK").unwrap();
    let fvk =
        decode_extended_full_viewing_key(NETWORK.hrp_sapling_extended_full_viewing_key(), &ivk)
            .unwrap()
            .unwrap();

    let fvks = &vec![fvk];

    c.bench_function("scan all", |b| {
        b.iter(|| {
            let r = Runtime::new().unwrap();
            r.block_on(scan_all(fvks.clone().as_slice())).unwrap();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = scan);
criterion_main!(benches);
