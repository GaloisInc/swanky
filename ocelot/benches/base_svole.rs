// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector OLE benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::{
    ot::{KosReceiver, KosSender},
    svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
        copee::{Receiver as CpReceiver, Sender as CpSender},
        SVoleReceiver,
        SVoleSender,
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

fn svole_init<
    BVSender: SVoleSender + Sync + Send + 'static,
    BVReceiver: SVoleReceiver + Sync + Send,
>() -> (Arc<Mutex<BVSender>>, Arc<Mutex<BVReceiver>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        BVSender::init(&mut channel, &mut rng).unwrap()
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let vole_receiver = BVReceiver::init(&mut channel, &mut rng).unwrap();
    let vole_sender = handle.join().unwrap();
    let vole_sender = Arc::new(Mutex::new(vole_sender));
    let vole_receiver = Arc::new(Mutex::new(vole_receiver));
    (vole_sender, vole_receiver)
}

fn bench_svole<
    BVSender: SVoleSender + Sync + Send + 'static,
    BVReceiver: SVoleReceiver + Sync + Send,
>(
    vole_sender: &Arc<Mutex<BVSender>>,
    vole_receiver: &Arc<Mutex<BVReceiver>>,
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
    c.bench_function("base_svole::extend::Fp (N = 1024)", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<BVSender<Fp>, BVReceiver<Fp>>(&vole_sender, &vole_receiver, 1024);
        })
    });
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("base_svole::extend::Gf128 (N = 1024)", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<BVSender<Gf128>, BVReceiver<Gf128>>(&vole_sender, &vole_receiver, 1024);
        })
    });
}

fn bench_svole_init<BVSender: SVoleSender + Sync + Send + 'static, BVReceiver: SVoleReceiver>() {
    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        black_box(BVSender::init(&mut channel, &mut rng).unwrap())
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    black_box(BVReceiver::init(&mut channel, &mut rng).unwrap());
    handle.join().unwrap();
}

fn bench_svole_init_gf128(c: &mut Criterion) {
    c.bench_function("base_svole::init::Gf128", move |bench| {
        bench.iter(move || {
            bench_svole_init::<BVSender<Gf128>, BVReceiver<Gf128>>();
        });
    });
}

fn bench_svole_init_fp(c: &mut Criterion) {
    c.bench_function("base_svole::init::Fp", move |bench| {
        bench.iter(move || {
            bench_svole_init::<BVSender<Fp>, BVReceiver<Fp>>();
        });
    });
}

fn bench_svole_init_f2(c: &mut Criterion) {
    c.bench_function("base_svole::init::F2", move |bench| {
        bench.iter(move || {
            bench_svole_init::<BVSender<F2>, BVReceiver<F2>>();
        });
    });
}
criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_svole_fp, bench_svole_gf128, bench_svole_init_gf128, bench_svole_init_fp, bench_svole_init_f2
}
criterion_main!(svole);
