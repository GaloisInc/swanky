// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious transfer benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use scuttlebutt::{AesRng, Block};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Specifies the number of OTs to run when benchmarking OT extension.
const T: usize = 1 << 16;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}

fn _bench_block_ot<
    OTSender: ObliviousTransferSender<Msg = Block>,
    OTReceiver: ObliviousTransferReceiver<Msg = Block>,
>(
    bs: &[bool],
    ms: Vec<(Block, Block)>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        ot.send(&mut reader, &mut writer, &ms, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    ot.receive(&mut reader, &mut writer, &bs, &mut rng).unwrap();
    handle.join().unwrap();
}

fn _bench_block_cot<
    OTSender: CorrelatedObliviousTransferSender<Msg = Block>,
    OTReceiver: CorrelatedObliviousTransferReceiver<Msg = Block>,
>(
    bs: &[bool],
    deltas: Vec<Block>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        ot.send_correlated(&mut reader, &mut writer, &deltas, &mut rng)
            .unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    ot.receive_correlated(&mut reader, &mut writer, &bs, &mut rng)
        .unwrap();
    handle.join().unwrap();
}

fn _bench_block_rot<
    OTSender: RandomObliviousTransferSender<Msg = Block>,
    OTReceiver: RandomObliviousTransferReceiver<Msg = Block>,
>(
    bs: &[bool],
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = bs.len();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
        ot.send_random(&mut reader, &mut writer, m, &mut rng)
            .unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
    ot.receive_random(&mut reader, &mut writer, &bs, &mut rng)
        .unwrap();
    handle.join().unwrap();
}

type ChouOrlandiSender = chou_orlandi::ChouOrlandiOTSender;
type ChouOrlandiReceiver = chou_orlandi::ChouOrlandiOTReceiver;
type DummySender = dummy::DummyOTSender;
type DummyReceiver = dummy::DummyOTReceiver;
type NaorPinkasSender = naor_pinkas::NaorPinkasOTSender;
type NaorPinkasReceiver = naor_pinkas::NaorPinkasOTReceiver;

fn bench_ot(c: &mut Criterion) {
    c.bench_function("ot::ChouOrlandiOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(move || {
            _bench_block_ot::<ChouOrlandiSender, ChouOrlandiReceiver>(&bs, ms.clone())
        })
    });
    c.bench_function("ot::DummyOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(|| _bench_block_ot::<DummySender, DummyReceiver>(&bs, ms.clone()))
    });
    c.bench_function("ot::NaorPinkasOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(|| _bench_block_ot::<NaorPinkasSender, NaorPinkasReceiver>(&bs, ms.clone()))
    });
}

type AlszSender = alsz::AlszOTSender<ChouOrlandiReceiver>;
type AlszReceiver = alsz::AlszOTReceiver<ChouOrlandiSender>;
type KosSender = kos::KosOTSender<ChouOrlandiReceiver>;
type KosReceiver = kos::KosOTReceiver<ChouOrlandiSender>;

fn bench_otext(c: &mut Criterion) {
    c.bench_function("ot::AlszOT", move |bench| {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_ot::<AlszSender, AlszReceiver>(&bs, ms.clone()))
    });
    c.bench_function("ot::KosOT", move |bench| {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_ot::<KosSender, KosReceiver>(&bs, ms.clone()))
    });
}

fn bench_correlated_otext(c: &mut Criterion) {
    c.bench_function("cot::AlszOT", move |bench| {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_cot::<AlszSender, AlszReceiver>(&bs, deltas.clone()))
    });
    c.bench_function("cot::KosOT", move |bench| {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_cot::<KosSender, KosReceiver>(&bs, deltas.clone()))
    });
}

fn bench_random_otext(c: &mut Criterion) {
    c.bench_function("rot::AlszOT", move |bench| {
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_rot::<AlszSender, AlszReceiver>(&bs))
    });
    c.bench_function("rot::KosOT", move |bench| {
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_rot::<KosSender, KosReceiver>(&bs))
    });
}

criterion_group! {
    name = ot;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_ot, bench_otext, bench_correlated_otext, bench_random_otext
}

criterion_main!(ot);
