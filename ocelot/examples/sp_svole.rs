// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::svole::{
    base_svole::{BaseReceiver, BaseSender},
    svole_ext::sp_svole::{SpsReceiver, SpsSender},
};
use scuttlebutt::{
    field::{F61p, FiniteField as FF, Fp, Gf128, F2},
    AesRng, TrackChannel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::SystemTime,
};

fn test_spsvole<FE: FF>(len: usize) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);
        let start = SystemTime::now();
        let mut base_vole = BaseSender::<FE>::init(&mut channel, &mut rng).unwrap();
        let mut vole = SpsSender::<FE>::init(&mut channel, &mut rng, &mut base_vole, 1).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let _ = vole.send(&mut channel, len, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            len,
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = TrackChannel::new(reader, writer);
    let start = SystemTime::now();
    let mut base_vole = BaseReceiver::<FE>::init(&mut channel, &mut rng).unwrap();
    let mut vole = SpsReceiver::<FE>::init(&mut channel, &mut rng, &mut base_vole, 1).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = vole.receive(&mut channel, len, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        len,
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!(
        "Receiver communication (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver communication (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    let splen = 1 << 13;
    /*println!("\nField: F2 \n");
    _test_spsvole::<F2, BVSender<F2>, BVReceiver<F2>, SPSender<F2>, SPReceiver<F2>>(splen);
    println!("\nField: Gf128 \n");
    _test_spsvole::<Gf128, BVSender<Gf128>, BVReceiver<Gf128>, SPSender<Gf128>, SPReceiver<Gf128>>(
        splen,
    );
    println!("\nField: Fp \n");
    _test_spsvole::<Fp, BVSender<Fp>, BVReceiver<Fp>, SPSender<Fp>, SPReceiver<Fp>>(splen);*/
    println!("\nField: F61p \n");
    test_spsvole::<F61p>(splen);
}
