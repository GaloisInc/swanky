// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Private set intersection (PSTY) benchmarks using `criterion`.

use popsicle::psty::{Sender, P2};
use scuttlebutt::comm::{TrackReader, TrackWriter};
use scuttlebutt::AesRng;
use std::cell::RefCell;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::SystemTime;

const NBYTES: usize = 15;
const NTIMES: usize = 1 << 16;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(NBYTES)).collect()
}

fn psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = Rc::new(RefCell::new(TrackReader::new(BufReader::new(
            sender.try_clone().unwrap(),
        ))));
        let writer = Rc::new(RefCell::new(TrackWriter::new(BufWriter::new(sender))));

        let start = SystemTime::now();
        let mut p1 = P1::init(reader.clone(), writer.clone(), &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        p1.send(&inputs1, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            NTIMES,
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender communication (read): {:.2} Mb",
            reader.borrow().kilobits() / 1000.0
        );
        println!(
            "Sender communication (write): {:.2} Mb",
            writer.borrow().kilobits() / 1000.0
        );
    });

    let mut rng = AesRng::new();
    let reader = Rc::new(RefCell::new(TrackReader::new(BufReader::new(
        receiver.try_clone().unwrap(),
    ))));
    let writer = Rc::new(RefCell::new(TrackWriter::new(BufWriter::new(receiver))));

    let start = SystemTime::now();
    let mut p2 = P2::init(reader.clone(), writer.clone(), &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = p2.send(&inputs2, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        NTIMES,
        start.elapsed().unwrap().as_millis()
    );
    let _ = handle.join().unwrap();
    println!(
        "Receiver communication (read): {:.2} Mb",
        reader.borrow().kilobits() / 1000.0
    );
    println!(
        "Receiver communication (write): {:.2} Mb",
        writer.borrow().kilobits() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    let rs = rand_vec_vec(NTIMES);
    psty(rs.clone(), rs.clone());
}
