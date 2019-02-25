use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_thread(c: &mut Criterion) {
    c.bench_function("thread startup time", |b| {
        b.iter(|| {
            let h = std::thread::spawn(|| ());
            black_box(h);
        });
    });
}

fn bench_mutex(c: &mut Criterion) {
    c.bench_function("mutex lock time", |b| {
        let m = std::sync::Mutex::new(());
        b.iter(|| {
            let v = m.lock().unwrap();
            black_box(*v);
        });
    });
}

fn bench_rwlock_write(c: &mut Criterion) {
    c.bench_function("rwlock write time", |b| {
        let m = std::sync::RwLock::new(());
        b.iter(|| {
            let v = m.write().unwrap();
            black_box(*v);
        });
    });
}

fn bench_rwlock_read(c: &mut Criterion) {
    c.bench_function("rwlock read time", |b| {
        let m = std::sync::RwLock::new(());
        b.iter(|| {
            let v = m.read().unwrap();
            black_box(*v);
        });
    });
}

criterion_group!(
    benches,
    bench_thread,
    bench_mutex,
    bench_rwlock_write,
    bench_rwlock_read
);
criterion_main!(benches);
