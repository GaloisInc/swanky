// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::svole::{
    wykw::{Receiver, Sender},
    SVoleReceiver, SVoleSender,
};
use scuttlebutt::{
    field::{F61p, FiniteField as FF},
    AesRng, TrackChannel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::SystemTime,
};

fn run<FE: FF, VSender: SVoleSender<Msg = FE>, VReceiver: SVoleReceiver<Msg = FE>>() {
    let (sender, receiver) = UnixStream::pair().unwrap();
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
        let start = SystemTime::now();
        let voles = vole.send(&mut channel, &mut rng).unwrap();
        println!(
            "[{}] Send time (extend): {} ms",
            voles.len(),
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        vole.duplicate(&mut channel, &mut rng).unwrap();
        println!(
            "Send time (duplicate): {} ms",
            start.elapsed().unwrap().as_millis()
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
        "Send communication (init): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (init): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    channel.clear();
    let start = SystemTime::now();
    let voles = vole.receive(&mut channel, &mut rng).unwrap();
    println!(
        "[{}] Receive time (extend): {} ms",
        voles.len(),
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Send communication (extend): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (extend): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    channel.clear();
    let start = SystemTime::now();
    let _ = vole.duplicate(&mut channel, &mut rng).unwrap();
    println!(
        "Receive time (duplicate): {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Send communication (duplicate): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (duplicate): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    handle.join().unwrap();
}

fn main() {
    println!("\nField: F61p \n");
    run::<F61p, Sender<F61p>, Receiver<F61p>>()
}
