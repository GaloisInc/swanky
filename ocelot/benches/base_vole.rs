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
//use rand_core::{CryptoRng, RngCore};
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
    sync::{Arc, Mutex},
    time::Duration,
};

/// Specifies length of the input vector `u`
const T: usize = 1 << 10;

fn bench_svole_<
    ROTS: ROTSender + Malicious,
    ROTR: ROTReceiver + Malicious,
    FE: FF + Sync + Send,
    CPS: CopeeSender<Msg = FE>,
    CPR: CopeeReceiver<Msg = FE>,
    BVSender: SVoleSender<Msg = FE> + Sync + Send,
    BVReceiver: SVoleReceiver<Msg = FE> + Sync + Send,
>(
    sender_: Arc<Mutex<BVSender>>,
    receiver_: Arc<Mutex<BVReceiver>>,
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

type BVSender<FE: FF> = VoleSender<CpSender<KosSender, FE>, FE>;
type BVReceiver<FE: FF> = VoleReceiver<CpReceiver<KosReceiver, FE>, FE>;
fn bench_svole_fp(c: &mut Criterion) {
    c.bench_function("svole::", move |bench| {
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let svole_sender = Arc::new(Mutex::new(
            BVSender::<Fp>::init(&mut channel, &mut rng).unwrap(),
        ));
        let svole_receiver = Arc::new(Mutex::new(
            BVReceiver::<Fp>::init(&mut channel, &mut rng).unwrap(),
        ));
        bench.iter(move || {
            bench_svole_::<
                KosSender,
                KosReceiver,
                Fp,
                CpSender<KosSender, Fp>,
                CpReceiver<KosReceiver, Fp>,
                VoleSender<CpSender<KosSender, Fp>, Fp>,
                VoleReceiver<CpReceiver<KosReceiver, Fp>, Fp>,
            >(svole_sender, svole_receiver, T);
        })
    });
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("svole::", move |bench| {
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let svole_sender = Arc::new(Mutex::new(
            BVSender::<Gf128>::init(&mut channel, &mut rng).unwrap(),
        ));
        let svole_receiver = Arc::new(Mutex::new(
            BVReceiver::<Gf128>::init(&mut channel, &mut rng).unwrap(),
        ));
        bench.iter(move || {
            bench_svole_::<
                KosSender,
                KosReceiver,
                Gf128,
                CpSender<KosSender, Gf128>,
                CpReceiver<KosReceiver, Gf128>,
                VoleSender<CpSender<KosSender, Gf128>, Gf128>,
                VoleReceiver<CpReceiver<KosReceiver, Gf128>, Gf128>,
            >(svole_sender, svole_receiver, T);
        })
    });
}

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_svole_fp, bench_svole_gf128
}
criterion_main!(svole);
