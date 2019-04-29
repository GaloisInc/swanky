// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection (PSTY) benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use popsicle::psty::{P1, P2};
use scuttlebutt::{AesRng, Block512};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn bench_psty_init() {
    let (sender, receiver) = UnixStream::pair().unwrap();

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let _ = P1::init(&mut reader, &mut writer, &mut rng).unwrap();
    });

    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let _ = P2::init(&mut reader, &mut writer, &mut rng).unwrap();

    handle.join().unwrap();
}

fn bench_psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) -> (Vec<Block512>, Vec<Block512>) {
    let (sender, receiver) = UnixStream::pair().unwrap();

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut p1 = P1::init(&mut reader, &mut writer, &mut rng).unwrap();
        p1.send(&mut reader, &mut writer, &inputs1, &mut rng)
            .unwrap()
    });

    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut p2 = P2::init(&mut reader, &mut writer, &mut rng).unwrap();
    let p2_out = p2
        .send(&mut reader, &mut writer, &inputs2, &mut rng)
        .unwrap();

    let p1_out = handle.join().unwrap();

    (p1_out, p2_out)
}

fn bench_psi(c: &mut Criterion) {
    c.bench_function("psi::PSTY (initialization)", move |bench| {
        bench.iter(|| {
            let result = bench_psty_init();
            criterion::black_box(result)
        })
    });
    c.bench_function("psi::PSTY (n = 2^8)", move |bench| {
        let rs = rand_vec_vec(1 << 8);
        bench.iter(|| {
            let v = bench_psty(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
    c.bench_function("psi::PSTY (n = 2^12)", move |bench| {
        let rs = rand_vec_vec(1 << 12);
        bench.iter(|| {
            let v = bench_psty(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
    c.bench_function("psi::PSTY (n = 2^16)", move |bench| {
        let rs = rand_vec_vec(1 << 16);
        bench.iter(|| {
            let v = bench_psty(rs.clone(), rs.clone());
            criterion::black_box(v)
        })
    });
    // c.bench_function("psi::PSTY (n = 2^20)", move |bench| {
    //     let rs = rand_vec_vec(1 << 20);
    //     bench.iter(|| {
    //         let v = bench_psty(rs.clone(), rs.clone());
    //         criterion::black_box(v)
    //     })
    // });
}

criterion_group! {
    name = psi;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(2);
    targets = bench_psi
}

criterion_main!(psi);
