//! Oblivious transfer benchmarks using `criterion`.

use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::ot::{
    self, CorrelatedReceiver, CorrelatedSender, RandomReceiver, RandomSender, Receiver, Sender,
};
use scuttlebutt::{AesRng, Block, Channel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

/// Specifies the number of OTs to run when benchmarking OT extension.
const T: usize = 1 << 18;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}

fn _bench_block_ot<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block>>(
    bs: &[bool],
    ms: Vec<(Block, Block)>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
        ot.send(&mut channel, &ms, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    ot.receive(&mut channel, bs, &mut rng).unwrap();
    handle.join().unwrap();
}

fn _bench_block_cot<
    OTSender: CorrelatedSender<Msg = Block>,
    OTReceiver: CorrelatedReceiver<Msg = Block>,
>(
    bs: &[bool],
    deltas: Vec<Block>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
        ot.send_correlated(&mut channel, &deltas, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    ot.receive_correlated(&mut channel, bs, &mut rng).unwrap();
    handle.join().unwrap();
}

fn _bench_block_rot<
    OTSender: RandomSender<Msg = Block>,
    OTReceiver: RandomReceiver<Msg = Block>,
>(
    bs: &[bool],
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = bs.len();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
        ot.send_random(&mut channel, m, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    ot.receive_random(&mut channel, bs, &mut rng).unwrap();
    handle.join().unwrap();
}

fn bench_ot(c: &mut Criterion) {
    c.bench_function("ot::ChouOrlandiOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(move || {
            _bench_block_ot::<ot::ChouOrlandiSender, ot::ChouOrlandiReceiver>(&bs, ms.clone())
        })
    });
    c.bench_function("ot::DummyOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(|| _bench_block_ot::<ot::DummySender, ot::DummyReceiver>(&bs, ms.clone()))
    });
    c.bench_function("ot::NaorPinkasOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(|| {
            _bench_block_ot::<ot::NaorPinkasSender, ot::NaorPinkasReceiver>(&bs, ms.clone())
        })
    });
}

fn bench_otext(c: &mut Criterion) {
    c.bench_function("ot::AlszOT", move |bench| {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_ot::<ot::AlszSender, ot::AlszReceiver>(&bs, ms.clone()))
    });
    c.bench_function("ot::KosOT", move |bench| {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_ot::<ot::KosSender, ot::KosReceiver>(&bs, ms.clone()))
    });
}

fn bench_correlated_otext(c: &mut Criterion) {
    c.bench_function("cot::AlszOT", move |bench| {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_cot::<ot::AlszSender, ot::AlszReceiver>(&bs, deltas.clone()))
    });
    c.bench_function("cot::KosOT", move |bench| {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_cot::<ot::KosSender, ot::KosReceiver>(&bs, deltas.clone()))
    });
}

fn bench_random_otext(c: &mut Criterion) {
    c.bench_function("rot::AlszOT", move |bench| {
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_rot::<ot::AlszSender, ot::AlszReceiver>(&bs))
    });
    c.bench_function("rot::KosOT", move |bench| {
        let bs = rand_bool_vec(T);
        bench.iter(|| _bench_block_rot::<ot::KosSender, ot::KosReceiver>(&bs))
    });
}

criterion_group! {
    name = ot;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_ot, bench_otext, bench_correlated_otext, bench_random_otext
}

criterion_main!(ot);
