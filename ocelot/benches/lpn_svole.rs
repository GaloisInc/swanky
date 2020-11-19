// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector OLE (LPN-based) benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use generic_array::typenum::Unsigned;
use ocelot::{
    ot::{ChouOrlandiReceiver, ChouOrlandiSender, KosReceiver, KosSender},
    svole::{
        base_svole::{BaseReceiver, BaseSender},
        svole_ext::{
            lpn_params::{LpnExtendParams, LpnSetupParams},
            sp_svole::{Receiver as SpVoleReceiver, Sender as SpVoleSender},
            svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
            LpnsVoleReceiver,
            LpnsVoleSender,
        },
    },
};
use scuttlebutt::{
    field::{F61p, FiniteField, Fp, Gf128, F2},
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
/// `COLS`, `WEIGHT` should be power of `2` and `COLS >> ROWS`, `COLS >> WEIGHT` such that `COLS % WEIGHT == 0`.
const ROWS: usize = LpnSetupParams::ROWS;
const COLS: usize = LpnSetupParams::COLS;
const WEIGHT: usize = LpnSetupParams::WEIGHT;
const D: usize = LpnSetupParams::D;

type SPSender<FE> = SpVoleSender<ChouOrlandiReceiver, FE>;
type SPReceiver<FE> = SpVoleReceiver<ChouOrlandiSender, FE>;

type VSender<FE> = LpnVoleSender<FE>;
type VReceiver<FE> = LpnVoleReceiver<FE>;

fn svole_init<
    VSender: LpnsVoleSender + Sync + Send + 'static,
    VReceiver: LpnsVoleReceiver + Sync + Send,
>(
    rows: usize,
    cols: usize,
    d: usize,
    weight: usize,
) -> (Arc<Mutex<VSender>>, Arc<Mutex<VReceiver>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let pows = ocelot::svole::utils::gen_pows();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut base_vole = BaseSender::init(&mut channel, &pows, &mut rng).unwrap();
        VSender::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap()
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut base_vole = BaseReceiver::init(&mut channel, &pows, &mut rng).unwrap();
    /*let base_vs = base_vole
    .receive(&mut channel, rows + weight + r, &mut rng)
    .unwrap();*/
    let delta = base_vole.delta();
    let vole_receiver =
        VReceiver::init(&mut channel, rows, cols, d, weight, delta, &mut rng).unwrap();
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
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let vole_sender = vole_sender.clone();
    let pows = ocelot::svole::utils::gen_pows();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut vole_sender = vole_sender.lock().unwrap();
        let mut base_vole = BaseSender::init(&mut channel, &pows, &mut rng).unwrap();
        let base_uws = base_vole.send(&mut channel, 1000, &mut rng).unwrap();
        black_box(vole_sender.send(&mut channel, &base_uws, &mut rng)).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut vole_receiver = vole_receiver.lock().unwrap();
    let mut base_vole = BaseReceiver::init(&mut channel, &pows, &mut rng).unwrap();
    let base_vs = base_vole.receive(&mut channel, 1000, &mut rng).unwrap();
    let delta = base_vole.delta();
    black_box(vole_receiver.receive(&mut channel, base_vs.as_slice(), &mut rng)).unwrap();
    handle.join().unwrap();
}

fn bench_svole_fp(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::Fp", move |bench| {
        let (vole_sender, vole_receiver) = svole_init::<_, _, Fp>(ROWS, COLS, D, WEIGHT);
        bench.iter(move || {
            bench_svole::<VSender<Fp>, VReceiver<Fp>, Fp>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::Gf128", move |bench| {
        let (vole_sender, vole_receiver) = svole_init::<_, _, Gf128>(ROWS, COLS, D, WEIGHT);
        bench.iter(move || {
            bench_svole::<VSender<Gf128>, VReceiver<Gf128>, Fp>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_f2(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::F2", move |bench| {
        let (vole_sender, vole_receiver) = svole_init::<_, _, F2>(ROWS, COLS, D, WEIGHT);
        bench.iter(move || {
            bench_svole::<VSender<F2>, VReceiver<F2>, F2>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_f61p(c: &mut Criterion) {
    c.bench_function("lpn_svole::extend::F61p", move |bench| {
        let (vole_sender, vole_receiver) = svole_init::<_, _, F61p>(ROWS, COLS, D, WEIGHT);
        bench.iter(move || {
            bench_svole::<VSender<F61p>, VReceiver<F61p>, F61p>(&vole_sender, &vole_receiver);
        })
    });
}
fn bench_svole_init<
    VSender: LpnsVoleSender + Sync + Send + 'static,
    VReceiver: LpnsVoleReceiver,
    FE: FiniteField,
>(
    rows: usize,
    cols: usize,
    d: usize,
    weight: usize,
) {
    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    let pows = ocelot::svole::utils::gen_pows();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut base_vole = BaseSender::init(&mut channel, &pows, &mut rng).unwrap();
        let base_uws = base_vole
            .send(&mut channel, rows + weight + r, &mut rng)
            .unwrap();
        black_box(VSender::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap())
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let mut base_vole = BaseReceiver::init(&mut channel, &pows, &mut rng).unwrap();
    /*let base_vs = base_vole
    .receive(&mut channel, rows + weight + r, &mut rng)
    .unwrap();*/
    let delta = base_vole.delta();
    black_box(VReceiver::init(&mut channel, rows, cols, d, weight, delta, &mut rng).unwrap());
    handle.join().unwrap();
}

fn bench_svole_init_gf128(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::Gf128", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<Gf128>, VReceiver<Gf128>, Gf128>(ROWS, COLS, D, WEIGHT);
        });
    });
}

fn bench_svole_init_fp(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::Fp", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<Fp>, VReceiver<Fp>, Fp>(ROWS, COLS, D, WEIGHT);
        });
    });
}

fn bench_svole_init_f2(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::F2", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<F2>, VReceiver<F2>, F2>(ROWS, COLS, D, WEIGHT);
        });
    });
}

fn bench_svole_init_f61p(c: &mut Criterion) {
    c.bench_function("lpn_svole::init::F61p", move |bench| {
        bench.iter(move || {
            bench_svole_init::<VSender<F61p>, VReceiver<F61p>, F61p>(ROWS, COLS, D, WEIGHT);
        });
    });
}

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_svole_fp, bench_svole_gf128, bench_svole_f2, bench_svole_f61p, bench_svole_init_gf128, bench_svole_init_f61p, bench_svole_init_fp, bench_svole_init_f2
}
criterion_main!(svole);
