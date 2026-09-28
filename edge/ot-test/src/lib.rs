#![deny(missing_docs)]
//! Testing utilities for oblivious transfer protocols

use std::{
    fmt::Display,
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
};

use swanky_block::Block;
use swanky_channel_legacy::Channel;
use swanky_field_binary::F2;
use swanky_ot_traits::{
    CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, RandomReceiver, RandomSender,
    Receiver, Sender,
};
use swanky_rng::SwankyRng;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

fn rand_f2_vec(size: usize) -> Vec<F2> {
    (0..size).map(|_| rand::random::<F2>()).collect()
}

/// Test the functionality of an OT protocol by OT-ing `ninputs` blocks.
pub fn test_otext<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block> + Display>(
    ninputs: usize,
) {
    let m0s = rand_block_vec(ninputs);
    let m1s = rand_block_vec(ninputs);
    let bs = rand_f2_vec(ninputs);
    let m0s_ = m0s.clone();
    let m1s_ = m1s.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
        let ms = m0s.into_iter().zip(m1s).collect::<Vec<(Block, Block)>>();
        otext.send(&mut channel, &ms, &mut rng).unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let results = otext.receive(&mut channel, &bs, &mut rng).unwrap();
    handle.join().unwrap();
    for j in 0..ninputs {
        assert_eq!(results[j], if bs[j].into() { m1s_[j] } else { m0s_[j] })
    }
}

/// Test the functionality of a Correlated OT protocol by OT-ing `ninputs` blocks.
pub fn test_cotext<
    OTSender: CorrelatedSender<Msg = Block>,
    OTReceiver: CorrelatedReceiver<Msg = Block> + Display,
>(
    ninputs: usize,
) {
    let delta = rand::random::<Block>();
    let bs = rand_f2_vec(ninputs);
    let out = Arc::new(Mutex::new(vec![]));
    let out_ = out.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
        let mut out = out.lock().unwrap();
        *out = otext
            .send_correlated(&mut channel, ninputs, delta, &mut rng)
            .unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let results = otext
        .receive_correlated(&mut channel, &bs, &mut rng)
        .unwrap();
    handle.join().unwrap();
    let out_ = out_.lock().unwrap();
    for j in 0..ninputs {
        assert_eq!(
            results[j],
            if bs[j].into() {
                out_[j] ^ delta
            } else {
                out_[j]
            }
        )
    }
}

/// Test the functionality of a Random OT protocol by OT-ing `ninputs` blocks.
pub fn test_rotext<
    OTSender: RandomSender<Msg = Block>,
    OTReceiver: RandomReceiver<Msg = Block> + Display,
>(
    ninputs: usize,
) {
    let bs = rand_f2_vec(ninputs);
    let out = Arc::new(Mutex::new(vec![]));
    let out_ = out.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
        let mut out = out.lock().unwrap();
        *out = otext.send_random(&mut channel, ninputs, &mut rng).unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let results = otext.receive_random(&mut channel, &bs, &mut rng).unwrap();
    handle.join().unwrap();
    let out_ = out_.lock().unwrap();
    for j in 0..ninputs {
        assert_eq!(results[j], if bs[j].into() { out_[j].1 } else { out_[j].0 })
    }
}

/// Test the functionality of a Random OT protocol (with a fixed key) by OT-ing `ninputs` blocks.
pub fn test_rotext_fixed_key<
    OTSender: RandomSender<Msg = Block> + FixedKeyInitializer,
    OTReceiver: RandomReceiver<Msg = Block> + Display,
>(
    ninputs: usize,
) {
    let bs = rand_f2_vec(ninputs);
    let out = Arc::new(Mutex::new(vec![]));
    let out_ = out.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();

    let key = [1u8; 16];
    let key_ = key;

    let handle = std::thread::spawn(move || {
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTSender::init_fixed_key(&mut channel, key_, &mut rng).unwrap();
        let mut out = out.lock().unwrap();
        *out = otext.send_random(&mut channel, ninputs, &mut rng).unwrap();
    });
    let mut rng = SwankyRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let results = otext.receive_random(&mut channel, &bs, &mut rng).unwrap();
    handle.join().unwrap();
    let out_ = out_.lock().unwrap();
    for j in 0..ninputs {
        assert_eq!(results[j], if bs[j].into() { out_[j].1 } else { out_[j].0 })
    }
}

pub mod bench;
