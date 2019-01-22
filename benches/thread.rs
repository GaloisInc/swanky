use criterion::{criterion_main, criterion_group, Criterion, black_box};

fn bench_thread(c: &mut Criterion) {
    c.bench_function("thread startup time", |b| {
        b.iter(|| {
            let h = std::thread::spawn(||());
            black_box(h);
        });
    });
}

criterion_group!(benches, bench_thread);
criterion_main!(benches);
