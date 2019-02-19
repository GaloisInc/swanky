// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious transfer benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use scuttlebutt::Block;
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

type Reader = BufReader<UnixStream>;
type Writer = BufWriter<UnixStream>;

fn _bench_block_ot<
    OTSender: ObliviousTransferSender<Reader, Writer, Msg = Block>,
    OTReceiver: ObliviousTransferReceiver<Reader, Writer, Msg = Block>,
>(
    bs: &[bool],
    ms: Vec<(Block, Block)>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OTSender::init(&mut reader, &mut writer).unwrap();
        ot.send(&mut reader, &mut writer, &ms).unwrap();
    });
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OTReceiver::init(&mut reader, &mut writer).unwrap();
    ot.receive(&mut reader, &mut writer, &bs).unwrap();
    handle.join().unwrap();
}

fn _bench_block_cot<
    OTSender: CorrelatedObliviousTransferSender<Reader, Writer, Msg = Block>,
    OTReceiver: CorrelatedObliviousTransferReceiver<Reader, Writer, Msg = Block>,
>(
    bs: &[bool],
    deltas: Vec<Block>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OTSender::init(&mut reader, &mut writer).unwrap();
        ot.send_correlated(&mut reader, &mut writer, &deltas)
            .unwrap();
    });
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OTReceiver::init(&mut reader, &mut writer).unwrap();
    ot.receive_correlated(&mut reader, &mut writer, &bs)
        .unwrap();
    handle.join().unwrap();
}

fn _bench_block_rot<
    OTSender: RandomObliviousTransferSender<Reader, Writer, Msg = Block>,
    OTReceiver: RandomObliviousTransferReceiver<Reader, Writer, Msg = Block>,
>(
    bs: &[bool],
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = bs.len();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut ot = OTSender::init(&mut reader, &mut writer).unwrap();
        ot.send_random(&mut reader, &mut writer, m).unwrap();
    });
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut ot = OTReceiver::init(&mut reader, &mut writer).unwrap();
    ot.receive_random(&mut reader, &mut writer, &bs).unwrap();
    handle.join().unwrap();
}

type ChouOrlandiSender = chou_orlandi::ChouOrlandiOTSender<Reader, Writer>;
type ChouOrlandiReceiver = chou_orlandi::ChouOrlandiOTReceiver<Reader, Writer>;
type DummySender = dummy::DummyOTSender<Reader, Writer>;
type DummyReceiver = dummy::DummyOTReceiver<Reader, Writer>;
type NaorPinkasSender = naor_pinkas::NaorPinkasOTSender<Reader, Writer>;
type NaorPinkasReceiver = naor_pinkas::NaorPinkasOTReceiver<Reader, Writer>;

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

type AlszSender = alsz::AlszOTSender<Reader, Writer, ChouOrlandiReceiver>;
type AlszReceiver = alsz::AlszOTReceiver<Reader, Writer, ChouOrlandiSender>;
type KosSender = kos::KosOTSender<Reader, Writer, ChouOrlandiReceiver>;
type KosReceiver = kos::KosOTReceiver<Reader, Writer, ChouOrlandiSender>;

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
}

fn bench_random_otext(c: &mut Criterion) {
    c.bench_function("rot::AlszOT", move |bench| {
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_rot::<AlszSender, AlszReceiver>(&bs))
    });
}

criterion_group! {
    name = ot;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_ot, bench_otext, bench_correlated_otext, bench_random_otext
}

criterion_main!(ot);
