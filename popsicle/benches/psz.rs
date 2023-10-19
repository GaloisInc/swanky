#![allow(clippy::all)]
//! Private set intersection (PSZ) benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use popsicle::psz;
use scuttlebutt::{AesRng, Channel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn _bench_psz_init() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let _ = psz::Sender::init(&mut channel, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let _ = psz::Receiver::init(&mut channel, &mut rng).unwrap();
    handle.join().unwrap();
}

fn _bench_psz(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut psi = psz::Sender::init(&mut channel, &mut rng).unwrap();
        psi.send(&inputs1, &mut channel, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut psi = psz::Receiver::init(&mut channel, &mut rng).unwrap();
    let intersection = psi.receive(&inputs2, &mut channel, &mut rng).unwrap();
    handle.join().unwrap();
    intersection
}

fn bench_psi(c: &mut Criterion) {
    c.bench_function("psi::PSZ (initialization)", move |bench| {
        bench.iter(|| {
            let result = _bench_psz_init();
            criterion::black_box(result)
        })
    });
    c.bench_function("psi::PSZ (n = 2^8)", move |bench| {
        let rs = rand_vec_vec(1 << 8);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
    c.bench_function("psi::PSZ (n = 2^12)", move |bench| {
        let rs = rand_vec_vec(1 << 12);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
    c.bench_function("psi::PSZ (n = 2^16)", move |bench| {
        let rs = rand_vec_vec(1 << 16);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
    c.bench_function("psi::PSZ (n = 2^20)", move |bench| {
        let rs = rand_vec_vec(1 << 20);
        bench.iter(|| {
            let v = _bench_psz(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
}

criterion_group! {
    name = psi;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_psi
}

criterion_main!(psi);
