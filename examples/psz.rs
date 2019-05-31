// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use popsicle::psz::{PszReceiver, PszSender};
// use scuttlebutt::comm::{TrackReader, TrackWriter};
use scuttlebutt::{AesRng, Channel};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::SystemTime;

const NBYTES: usize = 15;
const NTIMES: usize = 1 << 20;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ntimes: usize, size: usize) -> Vec<Vec<u8>> {
    (0..ntimes).map(|_| rand_vec(size)).collect()
}

fn psi() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender_inputs = rand_vec_vec(NTIMES, NBYTES);
    let receiver_inputs = sender_inputs.clone();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let start = SystemTime::now();
        let mut psi = PszSender::init(&mut channel, &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        psi.send(&mut channel, &sender_inputs, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            NTIMES,
            start.elapsed().unwrap().as_millis()
        );
        // println!(
        //     "Sender communication (read): {:.2} Mb",
        //     reader.kilobits() / 1000.0
        // );
        // println!(
        //     "Sender communication (write): {:.2} Mb",
        //     writer.kilobits() / 1000.0
        // );
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let start = SystemTime::now();
    let mut psi = PszReceiver::init(&mut channel, &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = psi
        .receive(&mut channel, &receiver_inputs, &mut rng)
        .unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        NTIMES,
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    // println!(
    //     "Receiver communication (read): {:.2} Mb",
    //     reader.kilobits() / 1000.0
    // );
    // println!(
    //     "Receiver communication (write): {:.2} Mb",
    //     writer.kilobits() / 1000.0
    // );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    psi();
}
