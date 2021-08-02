// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use clap::{App, Arg, SubCommand};
use ocelot::edabits::{ReceiverConv, SenderConv};
use scuttlebutt::{field::F61p, AesRng, Channel};
use std::env;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

type Sender = SenderConv<F61p>;
type Receiver = ReceiverConv<F61p>;

const NUM_EDABITS: usize = 10_000;

fn run(num_edabits: usize, with_mult_connect: bool) -> std::io::Result<()> {
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
            Ok((stream_verifier, _addr)) => {
                let mut rng = AesRng::new();
                let start = Instant::now();
                let reader = BufReader::new(stream_verifier.try_clone().unwrap());
                let writer = BufWriter::new(stream_verifier);
                let mut channel = Channel::new(reader, writer);
                let mut fconv = Receiver::init(&mut channel, &mut rng).unwrap();

                let edabits = fconv
                    .random_edabits(&mut channel, &mut rng, num_edabits)
                    .unwrap();

                let r = fconv.conv(&mut channel, &mut rng, &edabits).unwrap();
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    } else {
        println!("Prover started");
        let stream_prover = TcpStream::connect("127.0.0.1:5527")?;

        let mut rng = AesRng::new();
        let start = Instant::now();
        let reader = BufReader::new(stream_prover.try_clone().unwrap());
        let writer = BufWriter::new(stream_prover);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = Sender::init(&mut channel, &mut rng).unwrap();

        let edabits = fconv
            .random_edabits(&mut channel, &mut rng, num_edabits)
            .unwrap();

        let _ = fconv.conv(&mut channel, &mut rng, &edabits).unwrap();
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let matches = App::new("Edabit conversion protocol")
        .arg(
            Arg::with_name("bucket")
                .short("b")
                .long("bucket")
                .value_name("BUCKET")
                .help("Set the bucket size")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("num_edabits")
                .short("n")
                .long("num")
                .value_name("NUM_OF_EDABITS")
                .help("Set the number of edabits")
                .takes_value(true)
                .default_value("UNSPECIFIED"),
        )
        .arg(
            Arg::with_name("mult_connect")
                .short("m")
                .long("mult-connect")
                .help("Using multiple connections")
                .takes_value(false),
        )
        .get_matches();
    let num_edabits =
        usize::from_str_radix(&matches.value_of("num_edabits").unwrap(), 10).unwrap_or(NUM_EDABITS);
    let with_mult_connections = matches.value_of("mult_connect").map_or(false, |_| true);
    println!("{:?}", with_mult_connections);
    run(num_edabits, with_mult_connections)
}
