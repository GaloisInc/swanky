// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection (PSTY) benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use popsicle::psty::{Sender, Receiver};
use scuttlebutt::AesRng;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use std::cell::RefCell;
use std::rc::Rc;

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
        let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
        let writer = Rc::new(RefCell::new(BufWriter::new(sender)));
        let _ = Sender::init(reader, writer, &mut rng).unwrap();
    });

    let mut rng = AesRng::new();
    let reader = Rc::new(RefCell::new(BufReader::new(receiver.try_clone().unwrap())));
    let writer = Rc::new(RefCell::new(BufWriter::new(receiver)));
    let _ = Receiver::init(reader, writer, &mut rng).unwrap();

    handle.join().unwrap();
}

fn bench_psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) -> Vec<popsicle::psty::Msg> {
    let (sender, receiver) = UnixStream::pair().unwrap();

    std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
        let writer = Rc::new(RefCell::new(BufWriter::new(sender)));
        let mut p1 = Sender::init(reader, writer, &mut rng).unwrap();
        p1.send(&inputs1, &mut rng).unwrap()
    });

    let mut rng = AesRng::new();
    let reader = Rc::new(RefCell::new(BufReader::new(receiver.try_clone().unwrap())));
    let writer = Rc::new(RefCell::new(BufWriter::new(receiver)));
    let mut p2 = Receiver::init(reader, writer, &mut rng).unwrap();
    p2.receive(&inputs2, &mut rng).unwrap()
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
