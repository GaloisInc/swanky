// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield vector oblivious linear evaluation benchmarks using `criterion`.

// TODO: criterion might not be the best choice for larger benchmarks.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::svole::wykw::{LPN_EXTEND_MEDIUM, LPN_SETUP_MEDIUM};
use ocelot::svole::{
    wykw::{Receiver, Sender},
    SVoleReceiver, SVoleSender,
};

use scuttlebutt::{
    field::{F128p, F61p, Gf128},
    AesRng, Channel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};

// TODO: re-enable ggm_utils benchmarks once we've sorted out the private modules issue.
/*#[path = "../src/svole/wykw/ggm_utils.rs"]
mod ggm_utils;*/

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
        VSender::init(&mut channel, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap()
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let vole_receiver =
        VReceiver::init(&mut channel, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap();
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
        let mut out = Vec::new();
        vole_sender.send(&mut channel, &mut rng, &mut out).unwrap();
        black_box(out);
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut vole_receiver = vole_receiver.lock().unwrap();
    let mut out = Vec::new();
    vole_receiver
        .receive(&mut channel, &mut rng, &mut out)
        .unwrap();
    black_box(out);
    handle.join().unwrap();
}

fn bench_svole_fp(c: &mut Criterion) {
    c.bench_function("svole::extend::F128p", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<Sender<F128p>, Receiver<F128p>>(&vole_sender, &vole_receiver);
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
        black_box(
            VSender::init(&mut channel, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap(),
        )
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    black_box(
        VReceiver::init(&mut channel, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap(),
    );
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
    c.bench_function("svole::init::F128p", move |bench| {
        bench.iter(move || {
            bench_svole_init::<Sender<F128p>, Receiver<F128p>>();
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

/*fn bench_ggm_<FE: FiniteField>(depth: usize, seed: Block, aes: &(Aes128, Aes128)) {
    let exp = 1 << depth;
    let mut vs = vec![FE::ZERO; exp];
    black_box(ggm_utils::ggm(depth, seed, aes, &mut vs));
}

fn bench_ggm(c: &mut Criterion) {
    let cols = 10_805_248;
    let weight = 1_319;
    let m = cols / weight;
    let depth = 128 - (m as u128 - 1).leading_zeros() as usize;
    let seed = rand::thread_rng().gen();
    let seed0 = rand::thread_rng().gen();
    let seed1 = rand::thread_rng().gen();
    c.bench_function("svole::ggm::F61p", move |bench| {
        let aes0 = Aes128::new(seed0);
        let aes1 = Aes128::new(seed1);
        bench.iter(move || {
            bench_ggm_::<F61p>(depth, seed, &(aes0.clone(), aes1.clone()));
        })
    });
}*/

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets =
        bench_svole_init_f61p,
        bench_svole_init_gf128,
        bench_svole_f61p,
        bench_svole_gf128,
        //bench_ggm,
        bench_svole_fp,
        bench_svole_init_fp
}
criterion_main!(svole);
