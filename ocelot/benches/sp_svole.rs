// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Single-point Subfield Vector OLE benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::{
    ot::{ChouOrlandiReceiver, ChouOrlandiSender, KosReceiver, KosSender},
    svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
        copee::{Receiver as CpReceiver, Sender as CpSender},
        svole_ext::{
            eq::{Receiver as EQReceiver, Sender as EQSender},
            sp_svole_dummy_ggmprime::{Receiver as SpVoleReceiver, Sender as SpVoleSender},
            SpsVoleReceiver,
            SpsVoleSender,
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
type BVSender<FE> = VoleSender<CpSender<KosSender, FE>, FE>;
type BVReceiver<FE> = VoleReceiver<CpReceiver<KosReceiver, FE>, FE>;

type SPSender<FE> = SpVoleSender<ChouOrlandiReceiver, FE, BVSender<FE>, EQSender<FE>>;
type SPReceiver<FE> = SpVoleReceiver<ChouOrlandiSender, FE, BVReceiver<FE>, EQReceiver<FE>>;

fn sp_svole_init<
    SPSender: SpsVoleSender + Sync + Send + 'static,
    SPReceiver: SpsVoleReceiver + Sync + Send,
>() -> (Arc<Mutex<SPSender>>, Arc<Mutex<SPReceiver>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        SPSender::init(&mut channel, &mut rng).unwrap()
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let spvole_receiver = SPReceiver::init(&mut channel, &mut rng).unwrap();
    let spvole_sender = handle.join().unwrap();
    let spvole_sender = Arc::new(Mutex::new(spvole_sender));
    let spvole_receiver = Arc::new(Mutex::new(spvole_receiver));
    (spvole_sender, spvole_receiver)
}

fn bench_svole<
    SPSender: SpsVoleSender + Sync + Send + 'static,
    SPReceiver: SpsVoleReceiver + Sync + Send,
>(
    spvole_sender: &Arc<Mutex<SPSender>>,
    spvole_receiver: &Arc<Mutex<SPReceiver>>,
    len: u128,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let spvole_sender = spvole_sender.clone();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut spvole_sender = spvole_sender.lock().unwrap();
        black_box(spvole_sender.send(&mut channel, len, &mut rng)).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut spvole_receiver = spvole_receiver.lock().unwrap();
    black_box(spvole_receiver.receive(&mut channel, len, &mut rng)).unwrap();
    handle.join().unwrap();
}

fn bench_sp_fp(c: &mut Criterion) {
    c.bench_function("sp_svole::extend::Fp (N = 1024)", move |bench| {
        let (vole_sender, vole_receiver) = sp_svole_init();
        bench.iter(move || {
            bench_svole::<SPSender<Fp>, SPReceiver<Fp>>(&vole_sender, &vole_receiver, 1024);
        })
    });
}

fn bench_sp_gf128(c: &mut Criterion) {
    c.bench_function("sp_svole::extend::Gf128 (N = 1024)", move |bench| {
        let (vole_sender, vole_receiver) = sp_svole_init();
        bench.iter(move || {
            bench_svole::<SPSender<Gf128>, SPReceiver<Gf128>>(&vole_sender, &vole_receiver, 1024);
        })
    });
}

fn bench_sp_f2(c: &mut Criterion) {
    c.bench_function("sp_svole::extend::F2 (N = 1024)", move |bench| {
        let (vole_sender, vole_receiver) = sp_svole_init();
        bench.iter(move || {
            bench_svole::<SPSender<Gf128>, SPReceiver<Gf128>>(&vole_sender, &vole_receiver, 1024);
        })
    });
}

fn bench_sp_init<SPSender: SpsVoleSender + Sync + Send + 'static, SPReceiver: SpsVoleReceiver>() {
    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        black_box(SPSender::init(&mut channel, &mut rng).unwrap())
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    black_box(SPReceiver::init(&mut channel, &mut rng).unwrap());
    handle.join().unwrap();
}

fn bench_sp_init_gf128(c: &mut Criterion) {
    c.bench_function("sp_svole::init::Gf128", move |bench| {
        bench.iter(move || {
            bench_sp_init::<SPSender<Gf128>, SPReceiver<Gf128>>();
        });
    });
}

fn bench_sp_init_fp(c: &mut Criterion) {
    c.bench_function("sp_svole::init::Fp", move |bench| {
        bench.iter(move || {
            bench_sp_init::<SPSender<Fp>, SPReceiver<Fp>>();
        });
    });
}

fn bench_sp_init_f2(c: &mut Criterion) {
    c.bench_function("sp_svole::init::F2", move |bench| {
        bench.iter(move || {
            bench_sp_init::<SPSender<F2>, SPReceiver<F2>>();
        });
    });
}
criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_sp_fp, bench_sp_gf128, bench_sp_f2, bench_sp_init_gf128, bench_sp_init_fp, bench_sp_init_f2
}
criterion_main!(svole);
