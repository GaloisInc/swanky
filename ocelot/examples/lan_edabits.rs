// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use clap::{App, Arg, SubCommand};
use ocelot::edabits::{ReceiverConv, SenderConv};
use scuttlebutt::{field::F61p, AbstractChannel, AesRng, Channel, SyncChannel};
use std::env;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

type Sender = SenderConv<F61p>;
type Receiver = ReceiverConv<F61p>;

const NUM_EDABITS: usize = 10_000;
const BUCKET_SIZE: usize = 5;

const VERIFIER: &str = "VERIFIER";
const PROVER: &str = "PROVER";

fn helper_server<C: AbstractChannel>(v: &[u8], c: &mut C) -> () {
    let r = c.read_u8().unwrap();
    println!("SERVER recv: {:?} {:?}", v.len(), r);

    c.write_u8(v[0] + 50).unwrap();
    c.flush();
}

fn helper_client<C: AbstractChannel>(v: &[u8], c: &mut C) -> () {
    c.write_u8(v[0] - 40).unwrap();
    c.flush();

    let r = c.read_u8().unwrap();
    println!("CLIENT recv: {:?} {:?}", v.len(), r);
}

//fn helper_client<C>(vec: &[u8], c: AbstractChannel<C>) -> () {}

fn run(
    whoami: &str,
    num_edabits: usize,
    bucket_size: usize,
    with_mult_connect: bool,
) -> std::io::Result<()> {
    println!("whoami: {:?}", whoami);
    println!("num_edabits: {:?}", num_edabits);
    println!("bucket_size: {:?}", bucket_size);
    println!("with multitiple connect: {:?}", with_mult_connect);

    let vec: Vec<u8> = vec![80, 81, 82, 83, 84, 85, 86, 87, 88, 89];

    if whoami == VERIFIER {
        println!("Verifier started");

        let listener = TcpListener::bind("127.0.0.1:5527")?;

        match listener.accept() {
            Ok((stream_verifier, _addr)) => {
                let mut rng = AesRng::new();
                let start = Instant::now();
                let reader = BufReader::new(stream_verifier.try_clone().unwrap());
                let writer = BufWriter::new(stream_verifier);
                let mut channel: SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>> =
                    SyncChannel::new(reader, writer);

                let mut bucket_connections_verifier = Vec::with_capacity(bucket_size);
                if with_mult_connect {
                    for _i in 0..bucket_size {
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
                }

                if with_mult_connect {
                    let mut handles = Vec::new();

                    let mut i = 0;
                    for mut bucket_channel in bucket_connections_verifier.into_iter() {
                        let mut locvec = Vec::with_capacity(2);
                        for j in 0..2 {
                            locvec.push(vec[i * 2 + j]);
                        }
                        let handle =
                            std::thread::spawn(move || helper_server(&locvec, &mut bucket_channel));
                        handles.push(handle);
                        i += 1;
                    }

                    for handle in handles {
                        handle.join().unwrap();
                    }
                }

                let mut fconv = Receiver::init(&mut channel, &mut rng).unwrap();

                let mut rng = AesRng::new();
                let start = Instant::now();

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
        let reader = BufReader::new(stream_prover.try_clone().unwrap());
        let writer = BufWriter::new(stream_prover);
        let mut channel = SyncChannel::new(reader, writer);

        let mut bucket_connections_prover = Vec::with_capacity(bucket_size);
        if with_mult_connect {
            for _i in 0..bucket_size {
                println!("P: attempt bucket connection");
                let bucket_stream = TcpStream::connect("127.0.0.1:5527")?;
                println!("PEER ADDR {:?}", bucket_stream.peer_addr());
                let reader = BufReader::new(bucket_stream.try_clone().unwrap());
                let writer = BufWriter::new(bucket_stream);
                let bucket_channel = SyncChannel::new(reader, writer);
                bucket_connections_prover.push(bucket_channel);
            }
        }

        if with_mult_connect {
            let mut handles = Vec::new();

            let mut i = 0;
            for mut bucket_channel in bucket_connections_prover.into_iter() {
                println!("SFDSFSDFDS {:?}", i * 2);
                let mut locvec = Vec::with_capacity(2);
                for j in 0..2 {
                    locvec.push(vec[i * 2 + j]);
                }
                let handle =
                    std::thread::spawn(move || helper_client(&locvec, &mut bucket_channel));
                handles.push(handle);
                i += 1;
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }

        let mut rng = AesRng::new();
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
                .value_name("BUCKET")
                .help("Set the bucket size")
                .takes_value(true)
                .required(false)
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
            Arg::with_name("mult_connect")
                .short("m")
                .long("mult-connect")
                .help("Using multiple connections"),
        )
        .get_matches();
    let whoami;
    println!("{:?}", matches.value_of("bucket"));
    println!("{:?}", matches.value_of("num_edabits"));
    println!("{:?}", matches.value_of("mult_connections"));
    if !matches.is_present("prover") {
        whoami = VERIFIER;
    } else {
        whoami = PROVER;
    }

    //map_or(VERIFIER, |_| PROVER);
    let bucket_size =
        usize::from_str_radix(&matches.value_of("bucket").unwrap(), 10).unwrap_or(BUCKET_SIZE);
    let with_mult_connections = matches.value_of("mult_connect").map_or(false, |_| true);
    let num_edabits =
        usize::from_str_radix(&matches.value_of("num_edabits").unwrap(), 10).unwrap_or(NUM_EDABITS);

    let with_mult_connections = matches.is_present("mult_connect");
    run(whoami, num_edabits, bucket_size, with_mult_connections)
}
