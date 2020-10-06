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
            sp_svole_dummy_ggmprime::{Receiver as SpsReceiver, Sender as SpsSender},
            svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
            LpnsVoleReceiver,
            LpnsVoleSender,
        },
    },
};
use scuttlebutt::{
    field::{FiniteField as FF, Fp, Gf128, F2},
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
        let mut vole = VSender::init(&mut channel, rows, cols, d, &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let _ = vole.send(&mut channel, weight, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            cols - rows,
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
    let mut vole = VReceiver::init(&mut channel, rows, cols, d, &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = vole.receive(&mut channel, weight, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        cols - rows,
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
    type CPSender<FE> = CpSender<KosSender, FE>;
    type CPReceiver<FE> = CpReceiver<KosReceiver, FE>;

    type BVSender<FE> = VoleSender<CPSender<FE>, FE>;
    type BVReceiver<FE> = VoleReceiver<CPReceiver<FE>, FE>;

    type SPSender<FE> = SpsSender<ChouOrlandiReceiver, FE, BVSender<FE>, EqSender<FE>>;
    type SPReceiver<FE> = SpsReceiver<ChouOrlandiSender, FE, BVReceiver<FE>, EqReceiver<FE>>;

    type VSender<FE> = LpnVoleSender<FE, BVSender<FE>, SPSender<FE>>;
    type VReceiver<FE> = LpnVoleReceiver<FE, BVReceiver<FE>, SPReceiver<FE>>;

    const COLS: [usize; 2] = [10608640, 649728];
    const ROWS: [usize; 2] = [589824, 36288];
    const WEIGHTS: [usize; 2] = [1295, 1269];
    const EXPS: [usize; 2] = [13, 9]; // exponents
    const D: usize = 10;
    let cols = 1 << 23;
    let weight = cols >> (23 - 10); // cols % weight == 0 should hold.
    let rows = 589824;
    let d = 2; // ideal value given in the Xios paper
    for _i in 0..1 {
        _test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
        //_test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
        //_test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);
    }
}
