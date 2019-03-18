// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious pseudorandom function benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::kkrt::{Output, Seed};
use ocelot::*;
use scuttlebutt::{AesRng, Block};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

const T: usize = 1 << 12;

fn _bench_oprf<
    OPRFSender: ObliviousPrfSender<Seed = Seed, Input = Block, Output = Output>,
    OPRFReceiver: ObliviousPrfReceiver<Input = Block, Output = Output>,
>(
    rs: &[Block],
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = rs.len();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut oprf = OPRFSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        let _ = oprf.send(&mut reader, &mut writer, m, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut oprf = OPRFReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    oprf.receive(&mut reader, &mut writer, rs, &mut rng)
        .unwrap();
    handle.join().unwrap();
}

type ChouOrlandiSender = chou_orlandi::ChouOrlandiOTSender;
type ChouOrlandiReceiver = chou_orlandi::ChouOrlandiOTReceiver;
type AlszSender = alsz::AlszOTSender<ChouOrlandiReceiver>;
type AlszReceiver = alsz::AlszOTReceiver<ChouOrlandiSender>;
type KkrtSender = kkrt::KkrtOPRFSender<AlszReceiver>;
type KkrtReceiver = kkrt::KkrtOPRFReceiver<AlszSender>;

fn bench_oprf(c: &mut Criterion) {
    c.bench_function("oprf::KkrtOPRF", move |bench| {
        let rs = rand_block_vec(T);
        bench.iter(|| _bench_oprf::<KkrtSender, KkrtReceiver>(&rs.clone()))
    });
}

fn bench_oprf_compute(c: &mut Criterion) {
    c.bench_function("oprf::KkrtOPRF::compute", move |bench| {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(receiver.try_clone().unwrap());
            let mut writer = BufWriter::new(receiver);
            let _ = KkrtReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let oprf = KkrtSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        handle.join().unwrap();
        let seed = Seed::default();
        let input = rand::random::<Block>();
        bench.iter(|| oprf.compute(&seed, &input))
    });
}

criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_oprf, bench_oprf_compute
}

criterion_main!(oprf);
