// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious pseudorandom function benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use scuttlebutt::{AesRng, Block};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

const T: usize = 1 << 16;

fn _bench_oprf<
    OPRFSender: ObliviousPrfSender<Seed = [u8; 64], Input = Block, Output = [u8; 64]>,
    OPRFReceiver: ObliviousPrfReceiver<Input = Block, Output = [u8; 64]>,
>(
    rs: &[Block],
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = rs.len();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OPRFSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        let _ = ot.send(&mut reader, &mut writer, m, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OPRFReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    ot.receive(&mut reader, &mut writer, rs, &mut rng).unwrap();
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

criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_oprf
}

criterion_main!(oprf);
