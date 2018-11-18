#[macro_use]
extern crate criterion;

use criterion::Criterion;
use std::time::Duration;

use std::thread;

// i was curious how long it takes to start a thread in rust
fn bench_thread_start(c: &mut Criterion) {
    c.bench_function("start_thread", move |b| {
        b.iter(|| {
            let handle = thread::spawn(|| 1);
            criterion::black_box(handle.join().unwrap());
        });
    });
}

criterion_group!{
    name = threads;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_thread_start
}

criterion_main!(threads);
