// -*- mode: rust; -*-
//
// This file is part of `twopac`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Benchmarks for semi-honest 2PC using `fancy-garbling`.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::circuit::Circuit;
// use ocelot::ot::{ChouOrlandiReceiver as OtReceiver, ChouOrlandiSender as OtSender};
use ocelot::ot::{DummyReceiver as OtReceiver, DummySender as OtSender};
use scuttlebutt::AesRng;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use twopac::{Evaluator, Garbler};

type Reader = BufReader<UnixStream>;
type Writer = BufWriter<UnixStream>;

fn circuit(fname: &str) -> Circuit {
    let mut circ = Circuit::parse(fname).unwrap();
    println!("{}", fname);
    circ.print_info().unwrap();
    circ
}

fn _bench_circuit(circ: &mut Circuit) {
    let mut circ_ = circ.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut gb =
            Garbler::<Reader, Writer, AesRng, OtSender>::new(reader, writer, &vec![0u16; 128], rng)
                .unwrap();
        circ_.eval(&mut gb).unwrap();
    });
    let rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut ev =
        Evaluator::<Reader, Writer, AesRng, OtReceiver>::new(reader, writer, &vec![0u16; 128], rng)
            .unwrap();
    circ.eval(&mut ev).unwrap();
    handle.join().unwrap();
}

fn bench_aes(c: &mut Criterion) {
    let mut circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("twopac::semi-honest (AES)", move |bench| {
        bench.iter(|| _bench_circuit(&mut circ))
    });
}

criterion_group! {
    name = semihonest;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes
}

criterion_main!(semihonest);
