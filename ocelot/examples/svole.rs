// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::svole::{
    wykw::{Receiver, Sender},
    SVoleReceiver,
    SVoleSender,
};
use scuttlebutt::{
    field::{F61p, FiniteField as FF},
    AesRng,
    TrackChannel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::SystemTime,
};

fn run<FE: FF, VSender: SVoleSender<Msg = FE>, VReceiver: SVoleReceiver<Msg = FE>>() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);
        let start = SystemTime::now();
        let mut vole = VSender::init(&mut channel, &mut rng).unwrap();
        println!(
            "Send time (init): {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender init communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender init communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );
        channel.clear();
        let start = SystemTime::now();
        let voles = vole.send(&mut channel, &mut rng).unwrap();
        println!(
            "[{}] Send time (extend): {} ms",
            voles.len(),
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender extend communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender extend communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = TrackChannel::new(reader, writer);
    let start = SystemTime::now();
    let mut vole = VReceiver::init(&mut channel, &mut rng).unwrap();
    println!(
        "Receive time (init): {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver init communication (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver init communication (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    channel.clear();
    let start = SystemTime::now();
    let voles = vole.receive(&mut channel, &mut rng).unwrap();
    println!(
        "[{}] Receiver time (extend): {} ms",
        voles.len(),
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!(
        "Receiver extend communication (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver extend communication (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    println!("\nField: F61p \n");
    run::<F61p, Sender<F61p>, Receiver<F61p>>()
}
