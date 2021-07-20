// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::edabits::{ReceiverConv, SenderConv};
use scuttlebutt::{channel::track_unix_channel_pair, field::F61p, AesRng};
use std::time::Instant;

type Sender = SenderConv<F61p>;
type Receiver = ReceiverConv<F61p>;

fn run() {
    let (mut sender, mut receiver) = track_unix_channel_pair();
    let n = 10_000;
    let handle = std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        {
            let mut cpu_set = nix::sched::CpuSet::new();
            cpu_set.set(1).unwrap();
            nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
        }
        let mut rng = AesRng::new();
        let start = Instant::now();
        let mut fconv_sender = Sender::init(&mut sender, &mut rng).unwrap();
        println!("Send time (init): {:?}", start.elapsed());
        let start = Instant::now();
        let edabits = fconv_sender
            .random_edabits(&mut sender, &mut rng, n)
            .unwrap();
        println!("Send time (random edabits): {:?}", start.elapsed());
        let start = Instant::now();
        let _ = fconv_sender.conv(&mut sender, &mut rng, &edabits).unwrap();
        println!("Send time (conv): {:?}", start.elapsed());
    });
    #[cfg(target_os = "linux")]
    {
        let mut cpu_set = nix::sched::CpuSet::new();
        cpu_set.set(3).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
    }
    let mut rng = AesRng::new();
    let start = Instant::now();
    let mut fconv_receiver = Receiver::init(&mut receiver, &mut rng).unwrap();
    println!("Receive time (init): {:?}", start.elapsed());
    println!(
        "Send communication (init): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (init): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    receiver.clear();
    let start = Instant::now();
    let edabits_mac = fconv_receiver
        .random_edabits(&mut receiver, &mut rng, n)
        .unwrap();
    println!("Receive time (random edabits): {:?}", start.elapsed());
    println!(
        "Send communication (random edabits): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (random edabits): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    receiver.clear();
    let start = Instant::now();
    fconv_receiver
        .conv(&mut receiver, &mut rng, &edabits_mac)
        .unwrap();
    println!("Receive time (conv): {:?}", start.elapsed());
    println!(
        "Send communication (conv): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (conv): {:.4} Mb",
        receiver.kilobits_written() / 1000.0
    );
    handle.join().unwrap();
}

fn main() {
    println!("\nField: F61p \n");
    run()
}
