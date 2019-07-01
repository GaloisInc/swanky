// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use popsicle::psty::{Receiver, Sender};
use scuttlebutt::{AesRng, TrackChannel};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::SystemTime;

const NBYTES: usize = 16;
const NINPUTS: usize = 1 << 20;
const PAYLOAD_SIZE: usize = 64;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psty_payload(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>, payloads: Vec<Vec<u8>>) {
    let payload_size = payloads[0].len();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);

        let start = SystemTime::now();
        let mut sender = Sender::init(&mut channel, &mut rng).unwrap();
        println!(
            "Sender :: init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let state = sender.send(&inputs1, &mut channel, &mut rng).unwrap();
        println!(
            "Sender :: send time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: pre-payload communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: pre-payloads communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );
        let start = SystemTime::now();
        let _ = state.receive_payloads(payload_size, &mut channel).unwrap();
        println!(
            "Sender :: payload intersection time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: total communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: total communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = TrackChannel::new(reader, writer);

    let start = SystemTime::now();
    let mut receiver = Receiver::init(&mut channel, &mut rng).unwrap();
    println!(
        "Receiver :: init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let state = receiver.receive(&inputs2, &mut channel, &mut rng).unwrap();
    println!(
        "Receiver :: receive time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    state.send_payloads(&payloads, &mut channel, &mut rng).unwrap();
    println!(
        "Receiver :: payload intersection time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let _ = handle.join().unwrap();
    println!(
        "Receiver :: communication (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: communication (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    println!(
        "* Running PSTY on {} inputs each of length {} bytes with {} byte payloads",
        NINPUTS, NBYTES, PAYLOAD_SIZE
    );
    let rs = rand_vec_vec(NINPUTS, NBYTES);
    let payloads = rand_vec_vec(NINPUTS, PAYLOAD_SIZE);
    psty_payload(rs.clone(), rs.clone(), payloads);
}
