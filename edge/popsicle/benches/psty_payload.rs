//! Private set intersection (PSTY) benchmarks using `criterion`.

use criterion::{Criterion, criterion_group, criterion_main};
use popsicle::psty_payload::{Receiver, Sender};
use swanky_block::Block512;
use swanky_rng::SwankyRng;

use rand::{CryptoRng, RngExt};

use std::time::Duration;

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values
        .into_iter()
        .map(|item| {
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0_u8; 64];
            res_block[..8].copy_from_slice(&value_bytes[..8]);
            Block512::from(res_block)
        })
        .collect()
}
fn rand_u64_vec<RNG: CryptoRng>(n: usize, modulus: u64, rng: &mut RNG) -> Vec<u64> {
    (0..n).map(|_| rng.random::<u64>() % modulus).collect()
}

fn bench_psty_payload_init() {
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let _ = Sender::init(channel, &mut rng).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();
            let _ = Receiver::init(channel, &mut rng).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_psty_payload(
    sender_inputs: Vec<Vec<u8>>,
    receiver_inputs: Vec<Vec<u8>>,
    payloads: Vec<Block512>,
    weights: Vec<Block512>,
) {
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let mut psi = Sender::init(channel, &mut rng).unwrap();
            // For small to medium sized sets where batching can occur accross all bins
            psi.full_protocol(&sender_inputs, &weights, channel, &mut rng)
                .unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();
            let mut psi = Receiver::init(channel, &mut rng).unwrap();
            // For small to medium sized sets where batching can occur accross all bins
            let _ = psi
                .full_protocol(&receiver_inputs, &payloads, channel, &mut rng)
                .unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_psi(c: &mut Criterion) {
    c.bench_function("psi::PSTY PAYLOAD (initialization)", move |bench| {
        bench.iter(|| {
            bench_psty_payload_init();
            std::hint::black_box(())
        })
    });
    c.bench_function("psi::PSTY PAYLOAD (n = 2^8)", move |bench| {
        let mut rng = SwankyRng::new();
        let rs = rand_vec_vec(1 << 8);
        let payload = int_vec_block512(rand_u64_vec(1 << 8, 1 << 30, &mut rng));
        bench.iter(|| {
            bench_psty_payload(rs.clone(), rs.clone(), payload.clone(), payload.clone());
            std::hint::black_box(())
        })
    });
    c.bench_function("psi::PSTY PAYLOAD (n = 2^12)", move |bench| {
        let mut rng = SwankyRng::new();
        let rs = rand_vec_vec(1 << 12);
        let payload = int_vec_block512(rand_u64_vec(1 << 12, 1 << 30, &mut rng));
        bench.iter(|| {
            bench_psty_payload(rs.clone(), rs.clone(), payload.clone(), payload.clone());
            std::hint::black_box(())
        })
    });
}

criterion_group! {
    name = psi;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_psi
}

criterion_main!(psi);
