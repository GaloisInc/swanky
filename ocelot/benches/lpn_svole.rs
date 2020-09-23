// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector OLE (LPN-based) benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::{
    ot::{ChouOrlandiReceiver, ChouOrlandiSender, KosReceiver, KosSender},
    svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
        copee::{Receiver as CpReceiver, Sender as CpSender},
        svole_ext::{
            eq::{Receiver as EQReceiver, Sender as EQSender},
            sp_svole_dummy_ggmprime::{Receiver as SpVoleReceiver, Sender as SpVoleSender},
            svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
            LpnsVoleReceiver,
            LpnsVoleSender,
        },
    },
};
use scuttlebutt::{
    field::{Fp, Gf128, F2},
    AesRng,
    Channel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Specifies the LPN parameters such as number of rows, columns of the matrix that each column of it is uniform subjective to have
///  `d` number of non-zero entries.

const ROWS: usize = 1 << 7;
const COLS: usize = 1 << 8;
const D: usize = 8;
const LEN: usize = COLS - ROWS;

type CPSender<FE> = CpSender<KosSender, FE>;
type CPReceiver<FE> = CpReceiver<KosReceiver, FE>;

type BVSender<FE> = VoleSender<CPSender<FE>, FE>;
type BVReceiver<FE> = VoleReceiver<CPReceiver<FE>, FE>;

type SPSender<FE> = SpVoleSender<ChouOrlandiReceiver, FE, BVSender<FE>, EQSender<FE>>;
type SPReceiver<FE> = SpVoleReceiver<ChouOrlandiSender, FE, BVReceiver<FE>, EQReceiver<FE>>;

type VSender<FE> = LpnVoleSender<FE, BVSender<FE>, SPSender<FE>>;
type VReceiver<FE> = LpnVoleReceiver<FE, BVReceiver<FE>, SPReceiver<FE>>;

fn svole_init<
    VSender: LpnsVoleSender + Sync + Send + 'static,
    VReceiver: LpnsVoleReceiver + Sync + Send,
>(
    rows: usize,
    cols: usize,
    d: usize,
) -> (Arc<Mutex<VSender>>, Arc<Mutex<VReceiver>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        VSender::init(&mut channel, rows, cols, d, &mut rng).unwrap()
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let vole_receiver = VReceiver::init(&mut channel, rows, cols, d, &mut rng).unwrap();
    let vole_sender = handle.join().unwrap();
    let vole_sender = Arc::new(Mutex::new(vole_sender));
    let vole_receiver = Arc::new(Mutex::new(vole_receiver));
    (vole_sender, vole_receiver)
}

fn bench_svole<
    VSender: LpnsVoleSender + Sync + Send + 'static,
    VReceiver: LpnsVoleReceiver + Sync + Send,
>(
    vole_sender: &Arc<Mutex<VSender>>,
    vole_receiver: &Arc<Mutex<VReceiver>>,
    len: usize,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let vole_sender = vole_sender.clone();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut vole_sender = vole_sender.lock().unwrap();
        black_box(vole_sender.send(&mut channel, len, &mut rng)).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut vole_receiver = vole_receiver.lock().unwrap();
    black_box(vole_receiver.receive(&mut channel, len, &mut rng)).unwrap();
    handle.join().unwrap();
}

fn bench_svole_fp(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::Fp", move |bench| {
        let (vole_sender, vole_receiver) = svole_init(ROWS, COLS, D);
        bench.iter(move || {
            bench_svole::<VSender<Fp>, VReceiver<Fp>>(&vole_sender, &vole_receiver, LEN);
        })
    });
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::Gf128", move |bench| {
        let (vole_sender, vole_receiver) = svole_init(ROWS, COLS, D);
        bench.iter(move || {
            bench_svole::<VSender<Gf128>, VReceiver<Gf128>>(&vole_sender, &vole_receiver, LEN);
        })
    });
}

fn bench_svole_f2(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::F2", move |bench| {
        let (vole_sender, vole_receiver) = svole_init(ROWS, COLS, D);
        bench.iter(move || {
            bench_svole::<VSender<F2>, VReceiver<F2>>(&vole_sender, &vole_receiver, LEN);
        })
    });
}

fn bench_svole_init<
    VSender: LpnsVoleSender + Sync + Send + 'static,
    VReceiver: LpnsVoleReceiver,
>(
    rows: usize,
    cols: usize,
    d: usize,
) {
    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        black_box(VSender::init(&mut channel, rows, cols, d, &mut rng).unwrap())
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    black_box(VReceiver::init(&mut channel, rows, cols, d, &mut rng).unwrap());
    handle.join().unwrap();
}

fn bench_svole_init_gf128(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::Gf128", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<Gf128>, VReceiver<Gf128>>(ROWS, COLS, D);
        });
    });
}

fn bench_svole_init_fp(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::Fp", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<Fp>, VReceiver<Fp>>(ROWS, COLS, D);
        });
    });
}

fn bench_svole_init_f2(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::F2", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<F2>, VReceiver<F2>>(ROWS, COLS, D);
        });
    });
}
criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_svole_fp, bench_svole_gf128, bench_svole_f2, bench_svole_init_gf128, bench_svole_init_fp, bench_svole_init_f2
}
criterion_main!(svole);
