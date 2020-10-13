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
            SpsVoleReceiver,
            SpsVoleSender,
        },
        SVoleReceiver,
        SVoleSender,
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

fn _test_spsvole<
    FE: FF,
    BVSender: SVoleSender<Msg = FE>,
    BVReceiver: SVoleReceiver<Msg = FE>,
    SPSender: SpsVoleSender<BVSender, Msg = FE>,
    SPReceiver: SpsVoleReceiver<BVReceiver, Msg = FE>,
>(
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
        let base_vole = BVSender::init(&mut channel, &mut rng).unwrap();
        let mut vole = SPSender::init(&mut channel, &mut rng, base_vole).unwrap();
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
    let base_vole = BVReceiver::init(&mut channel, &mut rng).unwrap();
    let mut vole = SPReceiver::init(&mut channel, &mut rng, base_vole).unwrap();
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

type CPSender<FE> = CpSender<KosSender, FE>;
type CPReceiver<FE> = CpReceiver<KosReceiver, FE>;

type BVSender<FE> = VoleSender<CPSender<FE>, FE>;
type BVReceiver<FE> = VoleReceiver<CPReceiver<FE>, FE>;

type SPSender<FE> = SpsSender<ChouOrlandiReceiver, FE, BVSender<FE>, EqSender<FE>>;
type SPReceiver<FE> = SpsReceiver<ChouOrlandiSender, FE, BVReceiver<FE>, EqReceiver<FE>>;

fn main() {
    /// This is called in LPN-svole iteratively with secure `t = 1324` number of times each with
    /// `1 << 14`.
    let splen = 1 << 14;
    let t = 1394;
    for _i in 0..t {
        //_test_spsvole::<F2, BVSender<F2>, BVReceiver<F2>, SPSender<F2>, SPReceiver<F2>>(splen);
        //_test_spsvole::<Gf128, SPSender<Gf128>, SPReceiver<Gf128>>(splen);
        _test_spsvole::<Fp, BVSender<Fp>, BVReceiver<Fp>, SPSender<Fp>, SPReceiver<Fp>>(splen);
    }
}
