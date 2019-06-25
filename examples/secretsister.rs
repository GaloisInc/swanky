// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use clap::{App, Arg};
use itertools::Itertools;
use popsicle::{MultiPartyReceiver, MultiPartySender};
use scuttlebutt::{AesRng, Block, TrackChannel};
use serde::Deserialize;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::ToSocketAddrs;
use std::net::{TcpListener, TcpStream};
use std::time::SystemTime;

#[derive(Debug, Deserialize, Clone)]
enum PartyConfig {
    Sender { address: String, port: String },
    Receiver { address: String, port: String },
}

impl PartyConfig {
    fn address(&self) -> String {
        match self {
            PartyConfig::Sender { address, .. } => address.clone(),
            PartyConfig::Receiver { address, .. } => address.clone(),
        }
    }

    fn port(&self) -> String {
        match self {
            PartyConfig::Sender { port, .. } => port.clone(),
            PartyConfig::Receiver { port, .. } => port.clone(),
        }
    }
}

fn main() {
    let matches = App::new("secretsister")
        .version("1.0")
        .author("Brent Carmer <bcarmer@galois.com>")
        .about("Multi-Party IPV6 Address Private Set Intersection using KMPRT")
        .arg(
            Arg::with_name("CONFIG_FILE")
                .short("c")
                .long("config")
                .help("Yaml config file.")
                .takes_value(true)
                .default_value("secretsister.yaml"),
        )
        .arg(Arg::with_name("PARTY_ID").help("Party id.").required(true))
        .arg(
            Arg::with_name("INPUT_FILE")
                .help("Sets the input file to use.")
                .required(true),
        )
        .arg(
            Arg::with_name("OUTPUT_FILE")
                .short("o")
                .help("Sets the input file to use."),
        )
        .setting(clap::AppSettings::ColorAlways)
        .get_matches();

    let config: Vec<PartyConfig> = serde_yaml::from_reader(
        &mut std::fs::File::open(matches.value_of("CONFIG_FILE").unwrap()).unwrap(),
    )
    .unwrap();

    let my_id = usize::from_str_radix(&matches.value_of("PARTY_ID").unwrap(), 10).unwrap();

    let input_file = std::fs::File::open(matches.value_of("INPUT_FILE").unwrap()).unwrap();
    let inputs = BufReader::new(input_file)
        .lines()
        .map(|s| ipv6_to_block(&s.unwrap()))
        .collect_vec();

    let mut cons = connect_to_parties(my_id, &config);
    let mut rng = AesRng::new();

    if my_id == 0 {
        let total_time = SystemTime::now();

        println!("[receiver] init");
        let init_time = SystemTime::now();
        let mut receiver = MultiPartyReceiver::init(&mut cons, &mut rng).unwrap();
        println!(
            "- init time: {} ms",
            init_time.elapsed().unwrap().as_millis()
        );

        println!("[receiver] receive");
        let receive_time = SystemTime::now();
        let intersection = receiver.receive(&inputs, &mut cons, &mut rng).unwrap();
        println!(
            "- receive time: {} ms",
            receive_time.elapsed().unwrap().as_millis()
        );
        println!("[receiver] intersection size: {}", intersection.len());

        println!("[receiver] communication info:");
        let mut total = 0.0;
        for (id, c) in cons {
            println!(
                "\tparty {:.2}: sent {:.2} mb, received {:.2} mb",
                id,
                c.kilobits_written() / 1000.0,
                c.kilobits_read() / 1000.0
            );
            total += c.kilobits_written();
            total += c.kilobits_read();
        }

        println!("\ttotal: {:.2} mb", total / 1000.0);
        println!(
            "- total time: {} ms",
            total_time.elapsed().unwrap().as_millis()
        );

        if let Some(filename) = matches.value_of("OUTPUT_FILE") {
            let mut f = std::fs::File::open(filename).unwrap();
            for blk in intersection {
                writeln!(f, "{}", block_to_ipv6(blk)).unwrap();
            }
        }
    } else {
        println!("[sender] init");
        let mut sender = MultiPartySender::init(my_id, &mut cons, &mut rng).unwrap();
        println!("[sender] send");
        sender.send(&inputs, &mut cons, &mut rng).unwrap();
    }
}

fn connect_to_parties(
    my_id: usize,
    config: &[PartyConfig],
) -> Vec<(
    usize,
    TrackChannel<BufReader<TcpStream>, BufWriter<TcpStream>>,
)> {
    println!("[connect_to_parties party {}]", my_id);
    // listen for connections from parties with ids less than me
    // spawn a thread to accept connections
    let my_config = config[my_id].clone();
    let nparties = config.len();
    let listener_thread = std::thread::spawn(move || {
        let listener = TcpListener::bind(format!("localhost:{}", my_config.port())).unwrap();
        listener
            .incoming()
            .take(my_id)
            .map(|stream| {
                let mut stream = stream.unwrap();
                let id = read_usize(&mut stream);
                println!("[{}] party {} connected to me", my_id, id);
                (id, stream)
            })
            .collect_vec()
    });

    // connect to parties with ids greater than me
    let mut cons = (0..nparties).map(|_| None).collect_vec();
    for (id, party) in config.iter().enumerate().skip(my_id + 1) {
        let addr = format!("{}:{}", party.address(), party.port())
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        // wait for connection
        let mut stream;
        loop {
            if let Ok(s) = TcpStream::connect(&addr) {
                stream = s;
                break;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        write_usize(my_id, &mut stream);
        println!("[{}] connected to party {}", my_id, id);
        cons[id] = Some((id, stream));
    }

    for (id, con) in listener_thread.join().unwrap().into_iter() {
        cons[id] = Some((id, con))
    }

    cons.into_iter()
        .flatten()
        .map(|(id, stream)| {
            (
                id,
                TrackChannel::new(
                    BufReader::new(stream.try_clone().unwrap()),
                    BufWriter::new(stream),
                ),
            )
        })
        .collect()
}

fn ipv6_to_block(addr: &str) -> Block {
    let mut nums = [0_u8; 16];
    for (i, hex) in addr.split(":").enumerate() {
        let x = u16::from_str_radix(hex, 16).unwrap();
        nums[2 * i + 1] = (x & 0xFF) as u8;
        nums[2 * i] = ((x >> 8) & 0xFF) as u8;
    }
    Block::from(nums)
}

fn block_to_ipv6(b: Block) -> String {
    let bs = <[u8; 16]>::from(b)
        .into_iter()
        .map(|byte| format!("{:02X}", byte))
        .collect_vec();
    bs.chunks(2).map(|pair| pair.concat()).join(":")
}

fn read_usize<R: Read>(r: &mut R) -> usize {
    let mut buf = [0; 8];
    r.read(&mut buf).unwrap();
    unsafe { std::mem::transmute(buf) }
}

fn write_usize<W: Write>(x: usize, w: &mut W) {
    let buf: [u8; 8] = unsafe { std::mem::transmute(x) };
    w.write(&buf).unwrap();
}
