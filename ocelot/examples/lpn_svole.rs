// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::{
    ot::{ChouOrlandiReceiver, ChouOrlandiSender, KosReceiver, KosSender},
    svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
        copee::{Receiver as CpReceiver, Sender as CpSender},
        svole_ext::{
            eq::{Receiver as EqReceiver, Sender as EqSender},
            lpn_params::{LpnExtendParams, LpnSetupParams},
            sp_svole::{Receiver as SpsReceiver, Sender as SpsSender},
            svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
            LpnsVoleReceiver,
            LpnsVoleSender,
        },
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

fn _test_lpnvole<
    FE: FF,
    VSender: LpnsVoleSender<Msg = FE>,
    VReceiver: LpnsVoleReceiver<Msg = FE>,
>(
    rows: usize,
    cols: usize,
    d: usize,
    weight: usize,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);
        let start = SystemTime::now();
        let mut vole = VSender::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
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
        let start = SystemTime::now();
        let _ = vole.send(&mut channel, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            cols - rows,
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
    let mut vole = VReceiver::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
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
    let start = SystemTime::now();
    let _ = vole.receive(&mut channel, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        cols - rows,
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
    type CPSender<FE> = CpSender<KosSender, FE>;
    type CPReceiver<FE> = CpReceiver<KosReceiver, FE>;

    type BVSender<FE> = VoleSender<CPSender<FE>, FE>;
    type BVReceiver<FE> = VoleReceiver<CPReceiver<FE>, FE>;

    type SPSender<FE> = SpsSender<ChouOrlandiReceiver, FE, EqSender<FE>>;
    type SPReceiver<FE> = SpsReceiver<ChouOrlandiSender, FE, EqReceiver<FE>>;

    type VSender<FE> = LpnVoleSender<FE, BVSender<FE>, SPSender<FE>>;
    type VReceiver<FE> = LpnVoleReceiver<FE, BVReceiver<FE>, SPReceiver<FE>>;

    let rows = LpnSetupParams::ROWS;
    let cols = LpnSetupParams::COLS;
    let weight = LpnSetupParams::WEIGHT;
    let d = LpnSetupParams::D;

    /* println!("\nField: F2 \n");
    _test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
    println!("\nField: Gf128 \n");
    _test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
    println!("\nField: Fp \n");
    _test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);*/
    println!("\nField: F61p \n");
    _test_lpnvole::<F61p, VSender<F61p>, VReceiver<F61p>>(rows, cols, d, weight);
}
