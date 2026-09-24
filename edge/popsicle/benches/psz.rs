//! Private set intersection (PSZ) benchmarks using `criterion`.

use criterion::{Criterion, criterion_group, criterion_main};
use popsicle::psz;
use std::time::Duration;
use swanky_rng::SwankyRng;

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn _bench_psz_init() {
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            psz::Sender::init(channel, &mut rng)
        },
        |channel| {
            let mut rng = SwankyRng::new();
            psz::Receiver::init(channel, &mut rng)
        },
    )
    .unwrap();
}

fn _bench_psz(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let (_, intersection) = swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let mut psi = psz::Sender::init(channel, &mut rng)?;
            psi.send(&inputs1, channel, &mut rng)
        },
        |channel| {
            let mut rng = SwankyRng::new();
            let mut psi = psz::Receiver::init(channel, &mut rng)?;
            psi.receive(&inputs2, channel, &mut rng)
        },
    )
    .unwrap();
    intersection
}

fn bench_psi(c: &mut Criterion) {
    c.bench_function("psi::PSZ (initialization)", move |bench| {
        bench.iter(|| {
            _bench_psz_init();
            std::hint::black_box(())
        })
    });
    c.bench_function("psi::PSZ (n = 2^8)", move |bench| {
        let rs = rand_vec_vec(1 << 8);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            std::hint::black_box(v)
        })
    });
    c.bench_function("psi::PSZ (n = 2^12)", move |bench| {
        let rs = rand_vec_vec(1 << 12);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            std::hint::black_box(v)
        })
    });
    c.bench_function("psi::PSZ (n = 2^16)", move |bench| {
        let rs = rand_vec_vec(1 << 16);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            std::hint::black_box(v)
        })
    });
    c.bench_function("psi::PSZ (n = 2^20)", move |bench| {
        let rs = rand_vec_vec(1 << 20);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            std::hint::black_box(v)
        })
    });
}

criterion_group! {
    name = psi;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_psi
}

criterion_main!(psi);
