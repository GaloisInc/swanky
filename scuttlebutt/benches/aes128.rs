use criterion::{black_box, criterion_group, criterion_main, Criterion};
use scuttlebutt::{Aes128, Block};

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("Aes128::new", |b| {
        let key = rand::random::<Block>();
        b.iter(|| {
            let aes = Aes128::new(black_box(key));
            criterion::black_box(aes)
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let block = rand::random::<Block>();
        b.iter(|| {
            let c = aes.encrypt(black_box(block));
            black_box(c)
        });
    });
}

fn bench_aes_encrypt8(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt_blocks<8>", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let blocks = rand::random::<[Block; 8]>();
        b.iter(|| {
            let c = aes.encrypt_blocks(black_box(blocks));
            black_box(c)
        });
    });
}

criterion_group! {
    name = aes128;
    config = Criterion::default();
    targets = bench_aes_new, bench_aes_encrypt, bench_aes_encrypt8
}
criterion_main!(aes128);
