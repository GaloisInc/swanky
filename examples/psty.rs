// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection (PSTY) benchmarks using `criterion`.

use popsicle::psty::{P1, P2};
use scuttlebutt::AesRng;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn psty(
    inputs1: Vec<Vec<u8>>,
    inputs2: Vec<Vec<u8>>,
) -> (
    Vec<ocelot::oprf::kkrt::Output>,
    Vec<ocelot::oprf::kkrt::Output>,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        let mut p1 = P1::init(&mut reader, &mut writer, &mut rng).unwrap();
        p1.send(&mut reader, &mut writer, &inputs1, &mut rng)
            .unwrap()
    });

    let mut rng = AesRng::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    let mut p2 = P2::init(&mut reader, &mut writer, &mut rng).unwrap();
    let p2_out = p2
        .send(&mut reader, &mut writer, &inputs2, &mut rng)
        .unwrap();

    let p1_out = handle.join().unwrap();

    (p1_out, p2_out)
}

fn main() {
    let rs = rand_vec_vec(1 << 12);
    let _v = psty(rs.clone(), rs.clone());
    println!("done");
}
