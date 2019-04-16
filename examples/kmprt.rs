// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::oprf::kkrt::{Output, Seed};
use ocelot::oprf::kmprt::{KmprtSingleReceiver, KmprtSingleSender};
use ocelot::oprf::{ProgrammableReceiver, ProgrammableSender};
use rand::Rng;
use scuttlebutt::{AesRng, Block};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

fn _test_opprf<
    S: ProgrammableSender<Seed = Seed, Input = Block, Output = Output>,
    R: ProgrammableReceiver<Seed = Seed, Input = Block, Output = Output>,
>(
    ninputs: usize,
    npoints: usize,
) {
    let inputs = rand_block_vec(ninputs);
    let mut rng = AesRng::new();
    let points = (0..npoints)
        .map(|_| (rng.gen::<Block>(), rng.gen::<Output>()))
        .collect::<Vec<(Block, Output)>>();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut oprf = S::init(&mut reader, &mut writer, &mut rng).unwrap();
        let _ = oprf
            .send(
                &mut reader,
                &mut writer,
                &points,
                npoints,
                ninputs,
                &mut rng,
            )
            .unwrap();
    });
    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut oprf = R::init(&mut reader, &mut writer, &mut rng).unwrap();
    let _ = oprf
        .receive(&mut reader, &mut writer, npoints, &inputs, &mut rng)
        .unwrap();
    handle.join().unwrap();
}

fn main() {
    _test_opprf::<KmprtSingleSender, KmprtSingleReceiver>(1, 8);
}
