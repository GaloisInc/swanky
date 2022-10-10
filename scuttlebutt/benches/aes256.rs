use criterion::{black_box, criterion_group, criterion_main, Criterion};
use scuttlebutt::{Aes256, Block};

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("Aes256::new", |b| {
        let key = rand::random::<[u8; 32]>();
        b.iter(|| {
            let aes = Aes256::new(black_box(&key));
            black_box(aes)
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Aes256::encrypt", |b| {
        let aes = Aes256::new(&rand::random::<[u8; 32]>());
        let block = rand::random::<Block>();
        b.iter(|| {
            let c = aes.encrypt(black_box(block));
            black_box(c)
        });
    });
}

fn bench_aes_encrypt8(c: &mut Criterion) {
    c.bench_function("Aes256::encrypt8", |b| {
        let aes = Aes256::new(&rand::random::<[u8; 32]>());
        let blocks = rand::random::<[Block; 8]>();
        b.iter(|| {
            let c = aes.encrypt8(black_box(blocks));
            black_box(c)
        });
    });
}

criterion_group! {
    name = aes256;
    config = Criterion::default();
    targets = bench_aes_new, bench_aes_encrypt, bench_aes_encrypt8
}
criterion_main!(aes256);
