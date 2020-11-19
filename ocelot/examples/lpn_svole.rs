// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use generic_array::typenum::Unsigned;
use ocelot::svole::{
    base_svole::{BaseReceiver, BaseSender},
    svole_ext::{
        lpn_params::{LpnExtendParams, LpnSetupParams},
        svole_lpn::{LpnReceiver, LpnSender},
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
// Run this example by passing feature "pass_base_voles".
#[cfg(feature = "pass_base_voles")]
fn _test_lpnvole<FE: FF>(
    rows0: usize,
    cols0: usize,
    weight0: usize,
    rows1: usize,
    cols1: usize,
    weight1: usize,
    d: usize,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let total = SystemTime::now();
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);
        let pows = ocelot::svole::utils::gen_pows();
        let start = SystemTime::now();
        // Generating base voles of length `k + t + r` using LPN_vole with smaller LPN  parameters.
        let mut base_vole = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let base_uws = base_vole
            .send(&mut channel, rows0 + weight0 + r, &mut rng)
            .unwrap();
        let mut lpn_setup_vole =
            LpnSender::init(&mut channel, rows0, cols0, d, weight0, base_uws, &mut rng).unwrap();
        let lpnvs = lpn_setup_vole.send(&mut channel, &mut rng).unwrap();
        // We just need `k + t + r` of voles.
        let base_uws: Vec<_> = (0..rows1 + weight1 + r).map(|i| lpnvs[i]).collect();
        let mut vole =
            LpnSender::init(&mut channel, rows1, cols1, d, weight1, base_uws, &mut rng).unwrap();
        println!(
            "[{}] Send time (init): {} ms",
            cols0,
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
        let _ = vole.send(&mut channel, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            cols1 - (rows1 + weight1 + r),
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
    let pows = ocelot::svole::utils::gen_pows();
    let start = SystemTime::now();
    let mut base_vole = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
    let base_vs = base_vole
        .receive(&mut channel, rows0 + weight0 + r, &mut rng)
        .unwrap();
    let delta = base_vole.delta();
    let mut lpn_vole = LpnReceiver::init(
        &mut channel,
        rows0,
        cols0,
        d,
        weight0,
        base_vs,
        delta,
        &mut rng,
    )
    .unwrap();
    let lpnvs = lpn_vole.receive(&mut channel, &mut rng).unwrap();
    let base_vs: Vec<_> = (0..rows1 + weight1 + r).map(|i| lpnvs[i]).collect();
    let mut vole = LpnReceiver::init(
        &mut channel,
        rows1,
        cols1,
        d,
        weight1,
        base_vs,
        delta,
        &mut rng,
    )
    .unwrap();
    println!(
        "[{}] Receive time (init): {} ms",
        cols0,
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
    let _ = vole.receive(&mut channel, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        cols1 - (rows1 + weight1 + r),
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
    let rows0 = LpnSetupParams::ROWS;
    let cols0 = LpnSetupParams::COLS;
    let weight0 = LpnSetupParams::WEIGHT;
    let d = LpnSetupParams::D;
    let rows1 = LpnExtendParams::ROWS;
    let cols1 = LpnExtendParams::COLS;
    let weight1 = LpnExtendParams::WEIGHT;

    /*println!("\nField: F2 \n");
    _test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
    println!("\nField: Gf128 \n");
    _test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
    println!("\nField: Fp \n");
    _test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);*/
    println!("\nField: F61p \n");
    _test_lpnvole::<F61p>(rows0, cols0, weight0, rows1, cols1, weight1, d);
}
