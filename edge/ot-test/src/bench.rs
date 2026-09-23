//! Utilities to benchmark OT protocols using [`criterion`]
//!
//! WARN: the benchmarking approach employed in this module has limited accuracy due to spinning up
//! new threads for each benchmark iteration.

use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

use criterion::Criterion;
use swanky_block::Block;
use swanky_channel_legacy::Channel;
use swanky_field_binary::F2;
use swanky_ot_traits::{
    CorrelatedReceiver, CorrelatedSender, RandomReceiver, RandomSender, Receiver, Sender,
};
use swanky_rng::SwankyRng;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
fn rand_f2_vec(size: usize) -> Vec<F2> {
    (0..size).map(|_| rand::random::<F2>()).collect()
}

fn bench_block_ot_inner<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block>>(
    bs: &[F2],
    ms: Vec<(Block, Block)>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
        ot.send(&mut channel, &ms, &mut rng).unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    ot.receive(&mut channel, bs, &mut rng).unwrap();
    handle.join().unwrap();
}

/// Benchmark a 1-out-of-2 OT protocol using `size` inputs.
pub fn bench_block_ot<S: Sender<Msg = Block>, R: Receiver<Msg = Block>>(
    c: &mut Criterion,
    size: usize,
) {
    c.bench_function(
        &format!(
            "1-out-of-2 OT <{}, {}>",
            std::any::type_name::<S>(),
            std::any::type_name::<R>()
        ),
        |bench| {
            let m0s = rand_block_vec(size);
            let m1s = rand_block_vec(size);
            let ms = m0s.into_iter().zip(m1s).collect::<Vec<(Block, Block)>>();
            let bs = rand_f2_vec(size);
            bench.iter(move || bench_block_ot_inner::<S, R>(&bs, ms.clone()));
        },
    );
}

fn bench_block_cot_inner<
    OTSender: CorrelatedSender<Msg = Block>,
    OTReceiver: CorrelatedReceiver<Msg = Block>,
>(
    bs: &[F2],
    delta: Block,
) {
    let m = bs.len();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
        ot.send_correlated(&mut channel, m, delta, &mut rng)
            .unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    ot.receive_correlated(&mut channel, bs, &mut rng).unwrap();
    handle.join().unwrap();
}

/// Benchmark a correlated OT protocol with `size` inputs.
pub fn bench_correlated_ot<S: CorrelatedSender<Msg = Block>, R: CorrelatedReceiver<Msg = Block>>(
    c: &mut Criterion,
    size: usize,
) {
    c.bench_function(
        &format!(
            "Correlated OT <{}, {}>",
            std::any::type_name::<S>(),
            std::any::type_name::<R>()
        ),
        move |bench| {
            let delta = rand::random::<Block>();
            let bs = rand_f2_vec(size);
            bench.iter(|| bench_block_cot_inner::<S, R>(&bs, delta))
        },
    );
}

fn bench_block_rot_inner<
    OTSender: RandomSender<Msg = Block>,
    OTReceiver: RandomReceiver<Msg = Block>,
>(
    bs: &[F2],
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let m = bs.len();
    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
        ot.send_random(&mut channel, m, &mut rng).unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
    ot.receive_random(&mut channel, bs, &mut rng).unwrap();
    handle.join().unwrap();
}

/// Benchmark a random OT protocol with `size` inputs.
pub fn bench_random_ot<S: RandomSender<Msg = Block>, R: RandomReceiver<Msg = Block>>(
    c: &mut Criterion,
    size: usize,
) {
    c.bench_function(
        &format!(
            "Random OT <{}, {}>",
            std::any::type_name::<S>(),
            std::any::type_name::<R>()
        ),
        move |bench| {
            let bs = rand_f2_vec(size);
            bench.iter(|| bench_block_rot_inner::<S, R>(&bs))
        },
    );
}
