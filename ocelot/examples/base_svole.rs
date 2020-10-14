// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::{
    ot::{KosReceiver, KosSender},
    svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
        copee::{Receiver as CpReceiver, Sender as CpSender},
        svole_ext::lpn_params::{LpnExtendParams, LpnSetupParams},
        SVoleReceiver,
        SVoleSender,
    },
};
use scuttlebutt::{
    field::{F61p, FiniteField as FF, Fp, Gf128, F2},
    AesRng,
    TrackChannel,
};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::SystemTime,
};

type CPSender<FE> = CpSender<KosSender, FE>;
type CPReceiver<FE> = CpReceiver<KosReceiver, FE>;

fn _test_svole<FE: FF, BVSender: SVoleSender<Msg = FE>, BVReceiver: SVoleReceiver<Msg = FE>>(
    len: usize,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);
        let start = SystemTime::now();
        let mut vole = BVSender::init(&mut channel, &mut rng).unwrap();
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
    let mut vole = BVReceiver::init(&mut channel, &mut rng).unwrap();
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

type BVSender<FE> = VoleSender<CPSender<FE>, FE>;
type BVReceiver<FE> = VoleReceiver<CPReceiver<FE>, FE>;

fn main() {
    let len_setup_params = LpnSetupParams::ROWS;
    let len_extend_params = LpnExtendParams::ROWS;

    println!("Using LPN parameters for Init phase");
    println!("\nField: F2 \n");
    _test_svole::<F2, BVSender<F2>, BVReceiver<F2>>(len_setup_params);
    println!("\nField: Gf128 \n");
    _test_svole::<Gf128, BVSender<Gf128>, BVReceiver<Gf128>>(len_setup_params);
    println!("\nField: Fp \n");
    _test_svole::<Fp, BVSender<Fp>, BVReceiver<Fp>>(len_setup_params);
    println!("\nField: F61p \n");
    _test_svole::<F61p, BVSender<F61p>, BVReceiver<F61p>>(len_setup_params);

    println!("Using LPN parameters for Extend phase");
    println!("\nField: F2 \n");
    _test_svole::<F2, BVSender<F2>, BVReceiver<F2>>(len_extend_params);
    println!("\nField: Gf128 \n");
    _test_svole::<Gf128, BVSender<Gf128>, BVReceiver<Gf128>>(len_extend_params);
    println!("\nField: Fp \n");
    _test_svole::<Fp, BVSender<Fp>, BVReceiver<Fp>>(len_extend_params);
    println!("\nField: F61p \n");
    _test_svole::<F61p, BVSender<F61p>, BVReceiver<F61p>>(len_extend_params);
}
