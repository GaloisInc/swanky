// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! EQ protocol benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::svole::svole_ext::{
    eq::{Receiver as EQReceiver, Sender as EQSender},
    EqReceiver,
    EqSender,
};
use scuttlebutt::{
    field::{FiniteField, Fp, Gf128, F2},
    AesRng,
    Channel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

fn bench_eq<
    FE: FiniteField + Send,
    Eqsender: EqSender<Msg = FE>,
    Eqreceiver: EqReceiver<Msg = FE>,
>(
    input: FE,
) {
    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut eq_sender = Eqsender::init().unwrap();
        black_box(eq_sender.send(&mut channel, &input)).unwrap();
    });
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut eq_receiver = Eqreceiver::init().unwrap();
    black_box(eq_receiver.receive(&mut channel, &mut rng, &input)).unwrap();
    handle.join().unwrap();
}

fn bench_eq_fp(c: &mut Criterion) {
    c.bench_function("eq::send::Fp (input = Fp::ONE)", move |bench| {
        bench.iter(move || {
            bench_eq::<Fp, EQSender<Fp>, EQReceiver<Fp>>(Fp::ONE);
        })
    });
}

fn bench_eq_gf128(c: &mut Criterion) {
    c.bench_function("eq::send::Gf128 (input = Gf128::ONE)", move |bench| {
        bench.iter(move || {
            bench_eq::<Gf128, EQSender<Gf128>, EQReceiver<Gf128>>(Gf128::ONE);
        })
    });
}
fn bench_eq_f2(c: &mut Criterion) {
    c.bench_function("eq::send::F2 (input = F2::ONE)", move |bench| {
        bench.iter(move || {
            bench_eq::<F2, EQSender<F2>, EQReceiver<F2>>(F2::ONE);
        })
    });
}

criterion_group! {
    name = eq;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_eq_fp, bench_eq_gf128, bench_eq_f2
}
criterion_main!(eq);
