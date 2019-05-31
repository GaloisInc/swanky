// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::oprf::kmprt::{KmprtSingleReceiver, KmprtSingleSender};
use ocelot::oprf::{ProgrammableReceiver, ProgrammableSender};
use rand::Rng;
use scuttlebutt::{AesRng, Block, Block512, Channel};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

fn _test_opprf<
    S: ProgrammableSender<Seed = Block512, Input = Block, Output = Block512>,
    R: ProgrammableReceiver<Seed = Block512, Input = Block, Output = Block512>,
>(
    ninputs: usize,
    npoints: usize,
) {
    let inputs = rand_block_vec(ninputs);
    let mut rng = AesRng::new();
    let points = (0..npoints)
        .map(|_| (rng.gen(), rng.gen()))
        .collect::<Vec<(Block, Block512)>>();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut oprf = S::init(&mut channel, &mut rng).unwrap();
        let _ = oprf
            .send(&mut channel, &points, npoints, ninputs, &mut rng)
            .unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut oprf = R::init(&mut channel, &mut rng).unwrap();
    let _ = oprf
        .receive(&mut channel, npoints, &inputs, &mut rng)
        .unwrap();
    handle.join().unwrap();
}

fn main() {
    _test_opprf::<KmprtSingleSender, KmprtSingleReceiver>(1, 8);
}
