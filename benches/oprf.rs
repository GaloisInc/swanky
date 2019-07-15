// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious pseudorandom function benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
#[cfg(feature = "unstable")]
use ocelot::oprf::{
    kmprt::Hint, ProgrammableReceiver as OpprfReceiver, ProgrammableSender as OpprfSender,
};
use scuttlebutt::{AesRng, Block, Block512, Channel};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
#[cfg(feature = "unstable")]
fn rand_point_vec(size: usize) -> Vec<(Block, Block512)> {
    (0..size)
        .map(|_| rand::random::<(Block, Block512)>())
        .collect()
}

fn _bench_oprf_init<S: OprfSender, R: OprfReceiver>() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let _ = S::init(&mut channel, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let _ = R::init(&mut channel, &mut rng).unwrap();
    handle.join().unwrap();
}

fn _bench_oprf<S: OprfSender<Input = Block>, R: OprfReceiver<Input = Block>>(inputs: Vec<Block>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = inputs.len();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut oprf = S::init(&mut channel, &mut rng).unwrap();
        let _ = oprf.send(&mut channel, m, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut oprf = R::init(&mut channel, &mut rng).unwrap();
    oprf.receive(&mut channel, &inputs, &mut rng).unwrap();
    handle.join().unwrap();
}

fn bench_oprf(c: &mut Criterion) {
    c.bench_function("oprf::kkrt (initialization)", move |bench| {
        bench.iter(|| {
            let result = _bench_oprf_init::<oprf::KkrtSender, oprf::KkrtReceiver>();
            criterion::black_box(result);
        })
    });
    let inputs = rand_block_vec(1 << 12);
    c.bench_function("oprf::kkrt (n = 2^12)", move |bench| {
        bench.iter(|| {
            let result = _bench_oprf::<oprf::KkrtSender, oprf::KkrtReceiver>(inputs.clone());
            criterion::black_box(result);
        })
    });
    let inputs = rand_block_vec(1 << 16);
    c.bench_function("oprf::kkrt (n = 2^16)", move |bench| {
        bench.iter(|| {
            let result = _bench_oprf::<oprf::KkrtSender, oprf::KkrtReceiver>(inputs.clone());
            criterion::black_box(result);
        })
    });
    let inputs = rand_block_vec(1 << 18);
    c.bench_function("oprf::kkrt (n = 2^18)", move |bench| {
        bench.iter(|| {
            let result = _bench_oprf::<oprf::KkrtSender, oprf::KkrtReceiver>(inputs.clone());
            criterion::black_box(result);
        })
    });
}

fn bench_oprf_compute(c: &mut Criterion) {
    c.bench_function("oprf::kkrt (compute)", move |bench| {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(receiver.try_clone().unwrap());
            let writer = BufWriter::new(receiver);
            let mut channel = Channel::new(reader, writer);
            let _ = oprf::KkrtReceiver::init(&mut channel, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let oprf = oprf::KkrtSender::init(&mut channel, &mut rng).unwrap();
        handle.join().unwrap();
        let seed = rand::random::<Block512>();
        let input = rand::random::<Block>();
        bench.iter(|| {
            let result = oprf.compute(seed.clone(), input);
            criterion::black_box(result);
        })
    });
}

#[cfg(feature = "unstable")]
fn _bench_opprf<
    S: OpprfSender<Input = Block, Output = Block512>,
    R: OpprfReceiver<Input = Block, Output = Block512>,
>(
    points: Vec<(Block, Block512)>,
    inputs: Vec<Block>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let t = inputs.len();
    let n = points.len();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut oprf = S::init(&mut channel, &mut rng).unwrap();
        let _ = oprf
            .send(&mut channel, &points, points.len(), t, &mut rng)
            .unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut oprf = R::init(&mut channel, &mut rng).unwrap();
    oprf.receive(&mut channel, n, &inputs, &mut rng).unwrap();
    handle.join().unwrap();
}

#[cfg(feature = "unstable")]
fn bench_opprf(c: &mut Criterion) {
    c.bench_function("opprf::kmprt (t = 1, n = 2^2)", move |bench| {
        let inputs = rand_block_vec(1);
        let points = rand_point_vec(1 << 2);
        bench.iter(|| {
            let result = _bench_opprf::<
                oprf::kmprt::KmprtSingleSender,
                oprf::kmprt::KmprtSingleReceiver,
            >(points.clone(), inputs.clone());
            criterion::black_box(result);
        })
    });
    c.bench_function("opprf::kmprt (t = 2^4, n = 2^4)", move |bench| {
        let inputs = rand_block_vec(1 << 4);
        let points = rand_point_vec(1 << 4);
        bench.iter(|| {
            let result = _bench_opprf::<oprf::kmprt::KmprtSender, oprf::kmprt::KmprtReceiver>(
                points.clone(),
                inputs.clone(),
            );
            criterion::black_box(result);
        })
    });
    c.bench_function("opprf::kmprt (t = 2^8, n = 2^8)", move |bench| {
        let inputs = rand_block_vec(1 << 8);
        let points = rand_point_vec(1 << 8);
        bench.iter(|| {
            let result = _bench_opprf::<oprf::kmprt::KmprtSender, oprf::kmprt::KmprtReceiver>(
                points.clone(),
                inputs.clone(),
            );
            criterion::black_box(result);
        })
    });
}
#[cfg(feature = "unstable")]
fn bench_opprf_compute(c: &mut Criterion) {
    c.bench_function("opprf::kmprt (t = 1, compute)", move |bench| {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(receiver.try_clone().unwrap());
            let writer = BufWriter::new(receiver);
            let mut channel = Channel::new(reader, writer);
            let _ = oprf::kmprt::KmprtSingleReceiver::init(&mut channel, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let oprf = oprf::kmprt::KmprtSingleSender::init(&mut channel, &mut rng).unwrap();
        handle.join().unwrap();
        let seed = rand::random::<Block512>();
        let hint = Hint::rand(&mut rng, 8);
        let input = rand::random::<Block>();
        bench.iter(|| oprf.compute(&seed, &hint, &input))
    });
}

#[cfg(not(feature = "unstable"))]
criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(20);
    targets = bench_oprf, bench_oprf_compute
}
#[cfg(feature = "unstable")]
criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(20);
    targets = bench_opprf, bench_opprf_compute, bench_oprf, bench_oprf_compute
}

criterion_main!(oprf);
