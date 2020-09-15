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
use rand::SeedableRng;
use scuttlebutt::{
    field::{FiniteField as FF, Fp, Gf128},
    AesRng,
    Block,
    Channel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Specifies length of the input vector `u`
const T: usize = 1 << 10;

fn bench_svole_<
    FE: FF,
    BVSender: SVoleSender<Msg = FE> + Sync + Send + 'static,
    BVReceiver: SVoleReceiver<Msg = FE> + Sync + Send,
>(
    sender_: &mut Arc<Mutex<BVSender>>,
    receiver_: &mut Arc<Mutex<BVReceiver>>,
    len: usize,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let seed = rand::random::<Block>();
    let mut rng = AesRng::from_seed(seed);
    let sender_ = sender_.clone();
    let handle = std::thread::spawn(move || {
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut bv_sender = sender_.lock().unwrap();
        black_box(bv_sender.send(&mut channel, len, &mut rng)).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut bv_receiver = receiver_.lock().unwrap();
    black_box(bv_receiver.receive(&mut channel, len, &mut rng)).unwrap();
    handle.join().unwrap();
}

type BVSender<FE> = VoleSender<CpSender<KosSender, FE>, FE>;
type BVReceiver<FE> = VoleReceiver<CpReceiver<KosReceiver, FE>, FE>;

fn bench_svole_fp(c: &mut Criterion) {
    c.bench_function("svole::send::receive::Fp", move |bench| {
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut svole_sender = Arc::new(Mutex::new(
            BVSender::<Fp>::init(&mut channel, &mut rng).unwrap(),
        ));
        let mut svole_receiver = Arc::new(Mutex::new(
            BVReceiver::<Fp>::init(&mut channel, &mut rng).unwrap(),
        ));
        bench.iter(move || {
            bench_svole_::<Fp, BVSender<Fp>, BVReceiver<Fp>>(
                &mut svole_sender,
                &mut svole_receiver,
                T,
            );
        })
    });
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("svole::send::receive::Gf128", move |bench| {
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut svole_sender = Arc::new(Mutex::new(
            BVSender::<Gf128>::init(&mut channel, &mut rng).unwrap(),
        ));
        let mut svole_receiver = Arc::new(Mutex::new(
            BVReceiver::<Gf128>::init(&mut channel, &mut rng).unwrap(),
        ));
        bench.iter(move || {
            bench_svole_::<Gf128, BVSender<Gf128>, BVReceiver<Gf128>>(
                &mut svole_sender,
                &mut svole_receiver,
                T,
            );
        })
    });
}

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_svole_fp, bench_svole_gf128
}
criterion_main!(svole);
