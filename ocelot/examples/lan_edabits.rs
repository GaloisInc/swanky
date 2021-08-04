// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use clap::{App, Arg};
use ocelot::edabits::{ReceiverConv, SenderConv};
use scuttlebutt::{field::F61p, AesRng, SyncChannel};
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

type Sender = SenderConv<F61p>;
type Receiver = ReceiverConv<F61p>;

const DEFAULT_NB_BITS: usize = 38;
const DEFAULT_NUM_EDABITS: usize = 10_000;
const DEFAULT_NUM_BUCKET: usize = 5;

const VERIFIER: &str = "VERIFIER";
const PROVER: &str = "PROVER";

fn run(
    whoami: &str,
    nb_bits: usize,
    num_edabits: usize,
    num_bucket: usize,
    num_cut: usize,
    multithreaded: bool,
) -> std::io::Result<()> {
    println!("whoami: {:?}", whoami);
    println!("nb_bits: {:?}", nb_bits);
    println!("num_edabits: {:?}", num_edabits);
    println!("num_bucket: {:?}", num_bucket);
    println!("multithreaded: {:?}", multithreaded);

    if whoami == VERIFIER {
        println!("Verifier started");

        let listener = TcpListener::bind("127.0.0.1:5527")?;

        match listener.accept() {
            Ok((stream_verifier, _addr)) => {
                let reader = BufReader::new(stream_verifier.try_clone().unwrap());
                let writer = BufWriter::new(stream_verifier);
                let mut channel: SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>> =
                    SyncChannel::new(reader, writer);

                let mut bucket_connections = None;
                if multithreaded {
                    let mut bucket_connections_verifier = Vec::with_capacity(num_bucket);
                    for _i in 0..num_bucket {
                        match listener.accept() {
                            Ok((mstream, _addr)) => {
                                println!("V: receive bucket connection {:?}", _addr);
                                let bucket_stream = mstream;
                                let reader = BufReader::new(bucket_stream.try_clone().unwrap());
                                let writer = BufWriter::new(bucket_stream);
                                let bucket_channel = SyncChannel::new(reader, writer);
                                bucket_connections_verifier.push(bucket_channel);
                            }
                            Err(e) => println!("couldn't get client: {:?}", e),
                        }
                    }
                    bucket_connections = Some(bucket_connections_verifier);
                }
                let mut rng = AesRng::new();

                let start = Instant::now();
                let mut fconv = Receiver::init(&mut channel, &mut rng).unwrap();
                println!("Verifier time (init): {:?}", start.elapsed());

                let start = Instant::now();
                let edabits = fconv
                    .random_edabits(&mut channel, &mut rng, nb_bits, num_edabits)
                    .unwrap();
                println!("Verifier time (random edabits): {:?}", start.elapsed());

                let start = Instant::now();
                let r = fconv
                    .conv(
                        &mut channel,
                        &mut rng,
                        num_bucket,
                        num_cut,
                        &edabits,
                        bucket_connections,
                    )
                    .unwrap();
                println!("Verifier time (conv): {:?}", start.elapsed());
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    } else {
        println!("Prover started");
        let stream_prover = TcpStream::connect("127.0.0.1:5527")?;
        let reader = BufReader::new(stream_prover.try_clone().unwrap());
        let writer = BufWriter::new(stream_prover);
        let mut channel = SyncChannel::new(reader, writer);

        let mut bucket_connections = None;
        if multithreaded {
            let mut bucket_connections_prover = Vec::with_capacity(num_bucket);
            for _i in 0..num_bucket {
                println!("P: attempt bucket connection");
                let bucket_stream = TcpStream::connect("127.0.0.1:5527")?;
                println!("PEER ADDR {:?}", bucket_stream.peer_addr());
                let reader = BufReader::new(bucket_stream.try_clone().unwrap());
                let writer = BufWriter::new(bucket_stream);
                let bucket_channel = SyncChannel::new(reader, writer);
                bucket_connections_prover.push(bucket_channel);
            }
            bucket_connections = Some(bucket_connections_prover);
        }

        let mut rng = AesRng::new();
        let start = Instant::now();
        let mut fconv = Sender::init(&mut channel, &mut rng).unwrap();
        println!("Prover time (init): {:?}", start.elapsed());

        let start = Instant::now();
        let edabits = fconv
            .random_edabits(&mut channel, &mut rng, nb_bits, num_edabits)
            .unwrap();
        println!("Prover time (random edabits): {:?}", start.elapsed());

        let start = Instant::now();
        let _ = fconv
            .conv(
                &mut channel,
                &mut rng,
                num_bucket,
                num_cut,
                &edabits,
                bucket_connections,
            )
            .unwrap();
        println!("Prover time (conv): {:?}", start.elapsed());
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let matches = App::new("Edabit conversion protocol")
        .version("1.0")
        .author("Ben Razet")
        .about("")
        .arg(
            Arg::with_name("prover")
                .short("p")
                .long("prover")
                .help("set to be the prover")
                .required(false),
        )
        .arg(
            Arg::with_name("bucket")
                .short("b")
                .long("bucket")
                .value_name("NUM_BUCKET")
                .help("Set the number of buckets")
                .takes_value(true)
                .required(false)
                .default_value("UNSPECIFIED"),
        )
        .arg(
            Arg::with_name("nb_bits")
                .short("m")
                .long("nb_bits")
                .value_name("NB_BITS")
                .help("Set the number of bits in edabits")
                .takes_value(true)
                .default_value("UNSPECIFIED"),
        )
        .arg(
            Arg::with_name("num_edabits")
                .short("n")
                .long("num")
                .value_name("NUM_EDABITS")
                .help("Set the number of edabits")
                .takes_value(true)
                .default_value("UNSPECIFIED"),
        )
        .arg(
            Arg::with_name("multithreaded")
                .long("multithreaded")
                .help("Using multithreading"),
        )
        .get_matches();
    let whoami;
    println!("{:?}", matches.value_of("bucket"));
    println!("{:?}", matches.value_of("num_edabits"));
    println!("{:?}", matches.value_of("multithreaded"));
    if !matches.is_present("prover") {
        whoami = VERIFIER;
    } else {
        whoami = PROVER;
    }

    //map_or(VERIFIER, |_| PROVER);
    let num_bucket = usize::from_str_radix(&matches.value_of("bucket").unwrap(), 10)
        .unwrap_or(DEFAULT_NUM_BUCKET);
    let nb_bits =
        usize::from_str_radix(&matches.value_of("nb_bits").unwrap(), 10).unwrap_or(DEFAULT_NB_BITS);
    let num_edabits = usize::from_str_radix(&matches.value_of("num_edabits").unwrap(), 10)
        .unwrap_or(DEFAULT_NUM_EDABITS);

    let multithreaded = matches.is_present("multithreaded");
    let num_cut = num_bucket;
    run(
        whoami,
        nb_bits,
        num_edabits,
        num_bucket,
        num_cut,
        multithreaded,
    )
}
