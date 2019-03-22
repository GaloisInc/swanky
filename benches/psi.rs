// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use popsicle::psz::{PszReceiver, PszSender};
use popsicle::{PrivateSetIntersectionReceiver, PrivateSetIntersectionSender};
use scuttlebutt::AesRng;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const SIZE: usize = 16;

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
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let _ = PszSender::init(&mut reader, &mut writer, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let _ = PszReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    handle.join().unwrap();
}

fn _bench_psz(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut psi = PszSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        psi.send(&mut reader, &mut writer, &inputs1, &mut rng)
            .unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut psi = PszReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    let intersection = psi
        .receive(&mut reader, &mut writer, &inputs2, &mut rng)
        .unwrap();
    handle.join().unwrap();
    intersection
}

fn bench_oprf(c: &mut Criterion) {
    c.bench_function("psi::PSZ (initialization)", move |bench| {
        bench.iter(|| _bench_psz_init())
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
}

criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_oprf
}

criterion_main!(oprf);
