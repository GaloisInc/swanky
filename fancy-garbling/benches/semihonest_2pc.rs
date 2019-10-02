// -*- mode: rust; -*-
//
// This file is part of `twopac`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Benchmarks for semi-honest 2PC using `fancy-garbling`.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{
    circuit::Circuit,
    twopac::semihonest::{Evaluator, Garbler},
    FancyInput,
};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{AesRng, Channel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

type Reader = BufReader<UnixStream>;
type Writer = BufWriter<UnixStream>;
type MyChannel = Channel<Reader, Writer>;

fn circuit(fname: &str) -> Circuit {
    Circuit::parse(fname).unwrap()
}

fn _bench_circuit(circ: &Circuit, gb_inputs: Vec<u16>, ev_inputs: Vec<u16>) {
    let circ_ = circ.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let channel = Channel::new(reader, writer);
        let mut gb = Garbler::<MyChannel, AesRng, OtSender>::new(channel, rng).unwrap();
        let xs = gb.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        circ_.eval(&mut gb, &xs, &ys).unwrap();
    });
    let rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let channel = Channel::new(reader, writer);
    let mut ev = Evaluator::<MyChannel, AesRng, OtReceiver>::new(channel, rng).unwrap();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();
    circ.eval(&mut ev, &xs, &ys).unwrap();
    handle.join().unwrap();
}

fn bench_aes(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("twopac::semi-honest (AES)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 128], vec![0u16; 128]))
    });
}

fn bench_sha_1(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("twopac::semi-honest (SHA-1)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 512], vec![]))
    });
}

fn bench_sha_256(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("twopac::semi-honest (SHA-256)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 512], vec![]))
    });
}

criterion_group! {
    name = semihonest;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_aes, bench_sha_1, bench_sha_256,
}

criterion_main!(semihonest);
