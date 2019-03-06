// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious pseudorandom function benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use scuttlebutt::AesRng;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn rand_vec(t: usize) -> Vec<Vec<u8>> {
    (0..t)
        .map(|_| (0..64).map(|_| rand::random::<u8>()).collect::<Vec<u8>>())
        .collect()
}

const T: usize = 1 << 16;

fn _bench_oprf<
    OPRFSender: ObliviousPrfSender<Seed = (usize, Vec<u8>), Input = Vec<u8>, Output = (usize, Vec<u8>)>,
    OPRFReceiver: ObliviousPrfReceiver<Input = Vec<u8>, Output = (usize, Vec<u8>)>,
>(
    rs: &[Vec<u8>],
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

type KkrtSender = kkrt::KkrtOPRFSender<dummy::DummyVecOTReceiver>;
type KkrtReceiver = kkrt::KkrtOPRFReceiver<dummy::DummyVecOTSender>;

fn bench_oprf(c: &mut Criterion) {
    c.bench_function("oprf::KkrtOPRF", move |bench| {
        let rs = rand_vec(T);
        bench.iter(|| _bench_oprf::<KkrtSender, KkrtReceiver>(&rs.clone()))
    });
}

criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_oprf
}

criterion_main!(oprf);
