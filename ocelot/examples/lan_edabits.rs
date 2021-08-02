// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use clap::{App, Arg, SubCommand};
use ocelot::edabits::{ReceiverConv, SenderConv};
use scuttlebutt::{channel::track_unix_channel_pair, field::F61p, AesRng, Channel};
use std::env;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

type Sender = SenderConv<F61p>;
type Receiver = ReceiverConv<F61p>;

fn handle_client(mut stream: TcpStream) {
    println!("SDFDSFSDF");
    let mut x = [0; 1];
    stream.read(&mut x);
    println!("{:?}", x[0]);
    x[0] += 1;
    stream.write(&mut x);
}

fn run() -> std::io::Result<()> {
    let nb_edabits = 100_000;
    if env::args().len() <= 1 {
        println!("Verifier started");
        // for argument in env::args() {
        //     println!("{}", argument);
        // }
        let listener = TcpListener::bind("127.0.0.1:5527")?;

        // accept connections and process them serially
        // for stream in listener.incoming() {
        //     handle_client(stream?);
        // }
        match listener.accept() {
            Ok((stream_verifier, addr)) => {
                let mut rng = AesRng::new();
                let start = Instant::now();
                let reader = BufReader::new(stream_verifier.try_clone().unwrap());
                let writer = BufWriter::new(stream_verifier);
                let mut channel = Channel::new(reader, writer);
                let mut fconv = Receiver::init(&mut channel, &mut rng).unwrap();

                let edabits = fconv
                    .random_edabits(&mut channel, &mut rng, nb_edabits)
                    .unwrap();

                let r = fconv.conv(&mut channel, &mut rng, &edabits).unwrap();
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    } else {
        println!("Prover started");
        let mut stream_prover = TcpStream::connect("127.0.0.1:5527")?;

        let mut rng = AesRng::new();
        let start = Instant::now();
        let reader = BufReader::new(stream_prover.try_clone().unwrap());
        let writer = BufWriter::new(stream_prover);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = Sender::init(&mut channel, &mut rng).unwrap();

        let edabits = fconv
            .random_edabits(&mut channel, &mut rng, nb_edabits)
            .unwrap();

        let _ = fconv.conv(&mut channel, &mut rng, &edabits).unwrap();
    }
    Ok(())
    // let (mut sender, mut receiver) = track_unix_channel_pair();
    // let n = 100_000;
    // let handle = std::thread::spawn(move || {
    //     #[cfg(target_os = "linux")]
    //     {
    //         let mut cpu_set = nix::sched::CpuSet::new();
    //         cpu_set.set(1).unwrap();
    //         nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
    //     }
    //     let mut rng = AesRng::new();
    //     let start = Instant::now();
    //     let mut fconv_sender = Sender::init(&mut sender, &mut rng).unwrap();
    //     println!("Send time (init): {:?}", start.elapsed());
    //     let start = Instant::now();
    //     let edabits = fconv_sender
    //         .random_edabits(&mut sender, &mut rng, n)
    //         .unwrap();
    //     println!("Send time (random edabits): {:?}", start.elapsed());
    //     let start = Instant::now();
    //     let _ = fconv_sender.conv(&mut sender, &mut rng, &edabits).unwrap();
    //     println!("Send time (conv): {:?}", start.elapsed());
    // });
    // #[cfg(target_os = "linux")]
    // {
    //     let mut cpu_set = nix::sched::CpuSet::new();
    //     cpu_set.set(3).unwrap();
    //     nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
    // }
    // let mut rng = AesRng::new();
    // let start = Instant::now();
    // let mut fconv_receiver = Receiver::init(&mut receiver, &mut rng).unwrap();
    // println!("Receive time (init): {:?}", start.elapsed());
    // println!(
    //     "Send communication (init): {:.2} Mb",
    //     receiver.kilobits_read() / 1000.0
    // );
    // println!(
    //     "Receive communication (init): {:.2} Mb",
    //     receiver.kilobits_written() / 1000.0
    // );
    // receiver.clear();
    // let start = Instant::now();
    // let edabits_mac = fconv_receiver
    //     .random_edabits(&mut receiver, &mut rng, n)
    //     .unwrap();
    // println!("Receive time (random edabits): {:?}", start.elapsed());
    // println!(
    //     "Send communication (random edabits): {:.2} Mb",
    //     receiver.kilobits_read() / 1000.0
    // );
    // println!(
    //     "Receive communication (random edabits): {:.2} Mb",
    //     receiver.kilobits_written() / 1000.0
    // );
    // receiver.clear();
    // let start = Instant::now();
    // fconv_receiver
    //     .conv(&mut receiver, &mut rng, &edabits_mac)
    //     .unwrap();
    // println!("Receive time (conv): {:?}", start.elapsed());
    // println!(
    //     "Send communication (conv): {:.2} Mb",
    //     receiver.kilobits_read() / 1000.0
    // );
    // println!(
    //     "Receive communication (conv): {:.4} Mb",
    //     receiver.kilobits_written() / 1000.0
    // );
    // handle.join().unwrap();
}

fn main() -> std::io::Result<()> {
    println!("\nField: F61p \n");
    run()
}
