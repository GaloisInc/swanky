// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use generic_array::typenum::Unsigned;
use ocelot::svole::base_svole::{BaseReceiver, BaseSender};
use scuttlebutt::{
    field::{F61p, FiniteField as FF, Fp, Gf128, F2},
    AesRng, TrackChannel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::SystemTime,
};

// XXX copied here for now
fn gen_pows<FE: FF>() -> Vec<FE> {
    let mut acc = FE::ONE;
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    let mut pows = vec![FE::ZERO; r];
    for item in pows.iter_mut() {
        *item = acc;
        acc *= FE::GENERATOR;
    }
    pows
}

fn _test_svole<FE: FF>(len: usize) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);
        let pows = gen_pows();
        let start = SystemTime::now();
        let mut vole = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
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
    let pows = gen_pows();
    let start = SystemTime::now();
    let mut vole = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
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
    let len_setup_params = 19870;
    let len_extend_params = 589_760;

    println!("Using LPN parameters for Init phase");
    println!("\nField: F2 \n");
    _test_svole::<F2>(len_setup_params);
    println!("\nField: Gf128 \n");
    _test_svole::<Gf128>(len_setup_params);
    println!("\nField: Fp \n");
    _test_svole::<Fp>(len_setup_params);
    println!("\nField: F61p \n");
    _test_svole::<F61p>(len_setup_params);

    println!("Using LPN parameters for Extend phase");
    println!("\nField: F2 \n");
    _test_svole::<F2>(len_extend_params);
    println!("\nField: Gf128 \n");
    _test_svole::<Gf128>(len_extend_params);
    println!("\nField: Fp \n");
    _test_svole::<Fp>(len_extend_params);
    println!("\nField: F61p \n");
    _test_svole::<F61p>(len_extend_params);
}
