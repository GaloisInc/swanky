// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use clap::{App, Arg};
use ocelot::edabits::{ReceiverConv, SenderConv};
use scuttlebutt::{field::F61p, AesRng, SyncChannel, TrackChannel};
use std::fs;
use std::io::Write;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Instant;

type Sender = SenderConv<F61p>;
type Receiver = ReceiverConv<F61p>;

const DEFAULT_ADDR: &str = "127.0.0.1:5527";
const DEFAULT_NB_BITS: &str = "38";
const DEFAULT_NUM_EDABITS: &str = "10000";
const DEFAULT_NUM_BUCKET: &str = "5";

const VERIFIER: &str = "VERIFIER";
const PROVER: &str = "PROVER";

fn run(
    whoami: &str,
    connection_addr: &str,
    nb_bits: usize,
    num_edabits: usize,
    num_bucket: usize,
    num_cut: usize,
    multithreaded: bool,
    with_quicksilver: bool,
) -> std::io::Result<()> {
    println!("whoami: {:?}", whoami);
    println!("addr: {:?}", connection_addr);
    println!("nb_bits: {:?}", nb_bits);
    println!("num_edabits: {:?}", num_edabits);
    println!("num_bucket: {:?}", num_bucket);
    println!("with_quicksilver: {:?}", with_quicksilver);
    println!("multithreaded: {:?}", multithreaded);

    if whoami == VERIFIER {
        let filename = "/tmp/bench_result.txt";
        let mut file;
        if Path::new(filename).exists() {
            file = fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(filename)
                .unwrap();
        } else {
            file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .append(true)
                .open(filename)
                .unwrap();
        }

        println!("Verifier started");

        let listener = TcpListener::bind(connection_addr)?;

        match listener.accept() {
            Ok((stream_verifier, _addr)) => {
                println!("Verifier received a connection");
                let reader = BufReader::new(stream_verifier.try_clone().unwrap());
                let writer = BufWriter::new(stream_verifier);
                let mut channel: TrackChannel<
                    SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>,
                > = TrackChannel::new(SyncChannel::new(reader, writer));

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
                let end = start.elapsed();
                println!("Verifier time (init): {:?}", end);
                file.write_all(format!("init={:?}, ", end).as_bytes())?;
                let init_comm_sent = channel.kilobits_written();
                let init_comm_recv = channel.kilobits_read();
                channel.clear();

                let start = Instant::now();
                let edabits = fconv
                    .random_edabits(&mut channel, &mut rng, nb_bits, num_edabits)
                    .unwrap();
                let end = start.elapsed();
                println!("Verifier time (input random edabits): {:?}", end);
                file.write_all(format!("input={:?}, ", end).as_bytes())?;
                let input_comm_sent = channel.kilobits_written();
                let input_comm_recv = channel.kilobits_read();
                channel.clear();

                let start = Instant::now();
                let _r = fconv
                    .conv(
                        &mut channel,
                        &mut rng,
                        num_bucket,
                        num_cut,
                        &edabits,
                        bucket_connections,
                        with_quicksilver,
                    )
                    .unwrap();
                let end = start.elapsed();
                println!("Verifier time (conv): {:?}", start.elapsed());
                file.write_all(format!("conv={:?}, ", end).as_bytes())?;
                let conv_comm_sent = channel.kilobits_written();
                let conv_comm_recv = channel.kilobits_read();
                channel.clear();

                println!(
                    "Verifier communication sent (init): {:?} Mb",
                    init_comm_sent / 1000.0
                );
                file.write_all(
                    format!("v-comm-init={:.2}Mb, ", init_comm_sent / 1000.0).as_bytes(),
                )?;
                println!(
                    "Verifier communication sent (input): {:?} Mb",
                    input_comm_sent / 1000.0
                );
                file.write_all(
                    format!("v-comm-input={:.2}Mb, ", input_comm_sent / 1000.0).as_bytes(),
                )?;
                println!(
                    "Verifier communication sent (conv): {:?} Mb",
                    conv_comm_sent / 1000.0
                );
                file.write_all(
                    format!("v-comm-conv={:.2}Mb, ", conv_comm_sent / 1000.0).as_bytes(),
                )?;
                println!(
                    "Prover communication sent (init): {:?} Mb",
                    init_comm_recv / 1000.0
                );
                file.write_all(
                    format!("p-comm-init={:.2}Mb, ", init_comm_recv / 1000.0).as_bytes(),
                )?;
                println!(
                    "Prover communication sent (input): {:?} Mb",
                    input_comm_recv / 1000.0
                );
                file.write_all(
                    format!("p-comm-input={:.2}Mb, ", input_comm_recv / 1000.0).as_bytes(),
                )?;
                println!(
                    "Prover communication sent (conv): {:?} Mb",
                    conv_comm_recv / 1000.0
                );
                file.write_all(
                    format!("p-comm-conv={:.2}Mb\n", conv_comm_recv / 1000.0).as_bytes(),
                )?;
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    } else {
        println!("Prover started");
        let stream_prover = TcpStream::connect(connection_addr)?;
        let reader = BufReader::new(stream_prover.try_clone().unwrap());
        let writer = BufWriter::new(stream_prover);
        let mut channel = TrackChannel::new(SyncChannel::new(reader, writer));

        let mut bucket_connections = None;
        if multithreaded {
            let mut bucket_connections_prover = Vec::with_capacity(num_bucket);
            for _i in 0..num_bucket {
                println!("P: attempt bucket connection");
                let bucket_stream = TcpStream::connect(connection_addr)?;
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
        println!("Prover time (input random edabits): {:?}", start.elapsed());

        let start = Instant::now();
        let _ = fconv
            .conv(
                &mut channel,
                &mut rng,
                num_bucket,
                num_cut,
                &edabits,
                bucket_connections,
                with_quicksilver,
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
            Arg::with_name("addr")
                .long("addr")
                .value_name("ADDR")
                .help("Set addr for tcp connection")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_ADDR),
        )
        .arg(
            Arg::with_name("bucket")
                .short("b")
                .long("bucket")
                .value_name("NUM_BUCKET")
                .help("Set the number of buckets")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_NUM_BUCKET),
        )
        .arg(
            Arg::with_name("nb_bits")
                .short("m")
                .long("nb_bits")
                .value_name("NB_BITS")
                .help("Set the number of bits in edabits")
                .takes_value(true)
                .default_value(DEFAULT_NB_BITS),
        )
        .arg(
            Arg::with_name("num_edabits")
                .short("n")
                .long("num")
                .value_name("NUM_EDABITS")
                .help("Set the number of edabits")
                .takes_value(true)
                .default_value(DEFAULT_NUM_EDABITS),
        )
        .arg(
            Arg::with_name("with_quicksilver")
                .long("quicksilver")
                .help("use quicksilver")
                .required(false),
        )
        .arg(
            Arg::with_name("multithreaded")
                .long("multithreaded")
                .help("Using multithreading on B-loop"),
        )
        .get_matches();
    let whoami;
    if !matches.is_present("prover") {
        whoami = VERIFIER;
    } else {
        whoami = PROVER;
    }
    let connection_addr = &matches.value_of("addr").unwrap();
    let num_bucket = usize::from_str_radix(&matches.value_of("bucket").unwrap(), 10)
        .unwrap_or(usize::from_str_radix(DEFAULT_NUM_BUCKET, 10).unwrap());
    let nb_bits = usize::from_str_radix(&matches.value_of("nb_bits").unwrap(), 10)
        .unwrap_or(usize::from_str_radix(DEFAULT_NB_BITS, 10).unwrap());
    let num_edabits = usize::from_str_radix(&matches.value_of("num_edabits").unwrap(), 10)
        .unwrap_or(usize::from_str_radix(DEFAULT_NUM_EDABITS, 10).unwrap());

    let multithreaded = matches.is_present("multithreaded");
    let num_cut = num_bucket;
    let with_quicksilver = matches.is_present("with_quicksilver");
    run(
        whoami,
        connection_addr,
        nb_bits,
        num_edabits,
        num_bucket,
        num_cut,
        multithreaded,
        with_quicksilver,
    )
}
