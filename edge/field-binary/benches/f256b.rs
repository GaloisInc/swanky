use criterion::{Criterion, criterion_group, criterion_main};
use rand::RngExt;
use std::time::Duration;

use swanky_field_binary::F256b;
use vectoreyes::U8x32;

fn mul(c: &mut Criterion) {
    let mut rng = rand::rng();
    c.bench_function("f256b::mul", move |b| {
        b.iter_batched(
            || {
                let x = F256b::from(rng.random::<U8x32>());
                let y = F256b::from(rng.random::<U8x32>());
                (x, y)
            },
            |(mut x, y)| {
                x *= y;
                std::hint::black_box(x)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = f256b_benches;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = mul
}

criterion_main!(f256b_benches);
