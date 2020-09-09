// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector OLE benchmarks using `criterion`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ocelot::{
    ot::{KosReceiver, KosSender, RandomReceiver as ROTReceiver, RandomSender as ROTSender},
    svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
        copee::{Receiver as CpReceiver, Sender as CpSender},
        CopeeReceiver,
        CopeeSender,
        SVoleReceiver,
        SVoleSender,
    },
};
use rand::SeedableRng;
use scuttlebutt::{
    field::{FiniteField as FF, Fp, Gf128},
    AesRng,
    Block,
    Channel,
    Malicious,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

/// Specifies length of the input vector `u`
const T: usize = 1 << 10;

fn bench_svole_<
    ROTS: ROTSender + Malicious,
    ROTR: ROTReceiver + Malicious,
    FE: FF + Sync + Send,
    CPSender: CopeeSender<Msg = FE>,
    CPReceiver: CopeeReceiver<Msg = FE>,
    BVSender: SVoleSender<Msg = FE>,
    BVReceiver: SVoleReceiver<Msg = FE>,
>(
    len: usize,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let seed = rand::random::<Block>();
    let mut rng = AesRng::from_seed(seed);
    let handle = std::thread::spawn(move || {
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut svole_sender = BVSender::init(&mut channel, &mut rng).unwrap();
        black_box(svole_sender.send(&mut channel, len, &mut rng)).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut svole_receiver = BVReceiver::init(&mut channel, &mut rng).unwrap();
    black_box(svole_receiver.receive(&mut channel, len, &mut rng)).unwrap();
    handle.join().unwrap();
}

fn bench_svole(c: &mut Criterion) {
    c.bench_function("svole::WYKWSVole", move |bench| {
        bench.iter(move || {
            bench_svole_::<
                KosSender,
                KosReceiver,
                Fp,
                CpSender<KosSender, Fp>,
                CpReceiver<KosReceiver, Fp>,
                VoleSender<CpSender<KosSender, Fp>>,
                VoleReceiver<CpReceiver<KosReceiver, Fp>>,
            >(T);
            bench_svole_::<
                KosSender,
                KosReceiver,
                Gf128,
                CpSender<KosSender, Gf128>,
                CpReceiver<KosReceiver, Gf128>,
                VoleSender<CpSender<KosSender, Gf128>>,
                VoleReceiver<CpReceiver<KosReceiver, Gf128>>,
            >(T);
        })
    });
}

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_svole
}

criterion_main!(svole);
