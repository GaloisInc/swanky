// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use popsicle::psz::{PszReceiver, PszSender};
use popsicle::{PrivateSetIntersectionReceiver, PrivateSetIntersectionSender};
use scuttlebutt::{AesRng, Block};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

const T: usize = 1 << 8;

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

fn _bench_psz(inputs1: Vec<Block>, inputs2: Vec<Block>) {
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
    let _ = psi
        .receive(&mut reader, &mut writer, &inputs2, &mut rng)
        .unwrap();
    handle.join().unwrap();
}

fn bench_oprf(c: &mut Criterion) {
    c.bench_function("psi::PszPSI::Init", move |bench| {
        bench.iter(|| _bench_psz_init())
    });
    c.bench_function("psi::PszPSI", move |bench| {
        let rs = rand_block_vec(T);
        bench.iter(|| _bench_psz(rs.clone(), rs.clone()))
    });
}

criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_oprf
}

criterion_main!(oprf);
