// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield vector oblivious linear evaluation benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::svole::wykw::{Receiver, Sender};
use ocelot::svole::{SVoleReceiver, SVoleSender};
use scuttlebutt::{
    field::{F61p, Fp, Gf128, F2},
    AesRng, Channel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};

fn svole_init<
    VSender: SVoleSender + Sync + Send + 'static,
    VReceiver: SVoleReceiver + Sync + Send,
>() -> (Arc<Mutex<VSender>>, Arc<Mutex<VReceiver>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        VSender::init(&mut channel, &mut rng).unwrap()
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let vole_receiver = VReceiver::init(&mut channel, &mut rng).unwrap();
    let vole_sender = handle.join().unwrap();
    let vole_sender = Arc::new(Mutex::new(vole_sender));
    let vole_receiver = Arc::new(Mutex::new(vole_receiver));
    (vole_sender, vole_receiver)
}

fn bench_svole<
    VSender: SVoleSender + Sync + Send + 'static,
    VReceiver: SVoleReceiver + Sync + Send,
>(
    vole_sender: &Arc<Mutex<VSender>>,
    vole_receiver: &Arc<Mutex<VReceiver>>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let vole_sender = vole_sender.clone();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut vole_sender = vole_sender.lock().unwrap();
        black_box(vole_sender.send(&mut channel, &mut rng)).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut vole_receiver = vole_receiver.lock().unwrap();
    black_box(vole_receiver.receive(&mut channel, &mut rng)).unwrap();
    handle.join().unwrap();
}

fn bench_svole_fp(c: &mut Criterion) {
    c.bench_function("svole::extend::Fp", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<Sender<Fp>, Receiver<Fp>>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("svole::extend::Gf128", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<Sender<Gf128>, Receiver<Gf128>>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_f2(c: &mut Criterion) {
    c.bench_function("svole::extend::F2", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<Sender<F2>, Receiver<F2>>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_f61p(c: &mut Criterion) {
    c.bench_function("svole::extend::F61p", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<Sender<F61p>, Receiver<F61p>>(&vole_sender, &vole_receiver);
        })
    });
}
fn bench_svole_init<VSender: SVoleSender + Sync + Send + 'static, VReceiver: SVoleReceiver>() {
    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        black_box(VSender::init(&mut channel, &mut rng).unwrap())
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    black_box(VReceiver::init(&mut channel, &mut rng).unwrap());
    handle.join().unwrap();
}

fn bench_svole_init_gf128(c: &mut Criterion) {
    c.bench_function("svole::init::Gf128", move |bench| {
        bench.iter(move || {
            bench_svole_init::<Sender<Gf128>, Receiver<Gf128>>();
        });
    });
}

fn bench_svole_init_fp(c: &mut Criterion) {
    c.bench_function("svole::init::Fp", move |bench| {
        bench.iter(move || {
            bench_svole_init::<Sender<Fp>, Receiver<Fp>>();
        });
    });
}

fn bench_svole_init_f2(c: &mut Criterion) {
    c.bench_function("svole::init::F2", move |bench| {
        bench.iter(move || {
            bench_svole_init::<Sender<F2>, Receiver<F2>>();
        });
    });
}

fn bench_svole_init_f61p(c: &mut Criterion) {
    c.bench_function("svole::init::F61p", move |bench| {
        bench.iter(move || {
            bench_svole_init::<Sender<F61p>, Receiver<F61p>>();
        })
    });
}

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_svole_init_f61p, bench_svole_init_gf128, bench_svole_f61p, bench_svole_gf128
}
criterion_main!(svole);
