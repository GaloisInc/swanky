pub mod comm;
pub mod garble;

use crate::comm::{BinaryReceive, BinarySend};
use clap::{App, Arg, ErrorKind, SubCommand};
use failure::Error;
use fancy_garbling::fancy::{Fancy, HasModulus};
use fancy_garbling::garble::{Evaluator, Garbler, Message};
use std::fs;
use std::net::{TcpListener, TcpStream};

static VERSION: &str = "0.1.0";

pub fn main() {
    let matches = App::new("Fancy Two-party Secure Computation")
        .version(VERSION)
        .about("Runs two-party secure computation using fancy garbling")
        .global_setting(clap::AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("host")
                .long("host")
                .takes_value(true)
                .conflicts_with("file")
                .help("Host IP address")
                .global(true),
        )
        .arg(
            Arg::with_name("file")
                .long("file")
                .takes_value(true)
                .conflicts_with("host")
                .help("Communication file")
                .global(true),
        )
        .subcommand(SubCommand::with_name("garbler").about("Runs the garbler"))
        .subcommand(SubCommand::with_name("evaluator").about("Runs the evaluator"))
        .get_matches();

    let host = matches.value_of("host");
    let file = matches.value_of("file");

    let result = if let Some(_) = matches.subcommand_matches("garbler") {
        let input = vec![1];
        match (host, file) {
            (None, None) => Err(failure::err_msg("One of --host or --file must be used")),
            (Some(h), None) => match garbler_tcp(h) {
                Ok(mut stream) => garble(&mut stream, &input),
                Err(e) => Err(e),
            },
            (None, Some(f)) => match garbler_file(f) {
                Ok(mut stream) => garble(&mut stream, &input),
                Err(e) => Err(e),
            },
            (_, _) => unreachable!(),
        }
    } else if let Some(_) = matches.subcommand_matches("evaluator") {
        let input = vec![1];
        match (host, file) {
            (None, None) => Err(failure::err_msg("One of --host or --file must be used")),
            (Some(h), None) => match evaluator_tcp(h) {
                Ok(mut stream) => evaluate(&mut stream, &input),
                Err(e) => Err(e),
            },
            (None, Some(f)) => match evaluator_file(f) {
                Ok(mut stream) => evaluate(&mut stream, &input),
                Err(e) => Err(e),
            },
            (_, _) => unreachable!(),
        }
    } else {
        eprintln!(
            "{}",
            clap::Error::with_description("Missing subcommand", ErrorKind::InvalidSubcommand)
        );
        eprintln!("{}", matches.usage());
        std::process::exit(1);
    };
    match result {
        Ok(_) => (),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn circuit<F, W>(f: &mut F)
where
    W: HasModulus + Default + Clone,
    F: Fancy<Item = W>,
{
    let q = 17;
    let a = f.garbler_input(q);
    let b = f.evaluator_input(q);
    let c = f.add(&a, &b);
    f.output(&c);
}

fn garbler_file(file: &str) -> Result<impl BinarySend + BinaryReceive, Error> {
    println!("Creating file '{}'...", file);
    let f = fs::File::create(file)?;
    Ok(f)
}

fn garbler_tcp(host: &str) -> Result<impl BinarySend + BinaryReceive, Error> {
    println!("Launching server on '{}'...", host);
    let server = TcpListener::bind(host)?;
    println!("Success!");
    for stream in server.incoming() {
        let stream = stream?;
        return Ok(stream);
    }
    return Err(failure::err_msg("Unable to connect to stream"));
}

fn garble<S>(stream: &mut S, input: &[u16]) -> Result<(), Error>
where
    S: BinaryReceive + BinarySend,
{
    let mut input = input.into_iter();
    let mut callback = |msg: Message| {
        let msg = match msg {
            // Message::EvaluatorInputZero { zero, delta } => {
            //     Message::EvaluatorInput(zero.plus(&delta.cmul(0)))
            // }
            Message::GarblerInputZero { zero, delta } => {
                Message::GarblerInput(zero.plus(&delta.cmul(*input.next().unwrap())))
            }
            m => m,
        };
        stream
            .send(&msg.to_bytes())
            .expect("Unable to send message")
    };
    let mut gb = Garbler::new(&mut callback);
    circuit(&mut gb);
    Ok(())
}

fn evaluator_file(file: &str) -> Result<impl BinarySend + BinaryReceive, Error> {
    println!("Opening file '{}'...", file);
    let f = fs::File::open(file)?;
    Ok(f)
}

fn evaluator_tcp(host: &str) -> Result<impl BinarySend + BinaryReceive, Error> {
    println!("Connecting to server on '{}'...", host);
    let stream = TcpStream::connect(host)?;
    Ok(stream)
}

fn evaluate<S>(stream: &mut S, input: &[u16]) -> Result<(), Error>
where
    S: BinaryReceive + BinarySend,
{
    let mut input = input.into_iter();
    let mut callback = || {
        let bytes = stream.receive().expect("Failed to receive message");
        let msg = Message::from_bytes(&bytes).expect("Failed to convert bytes to message");
        match msg {
            Message::EvaluatorInputZero { zero, delta } => {
                Message::EvaluatorInput(zero.plus(&delta.cmul(*input.next().unwrap())))
            }
            m => m,
        }
    };
    let mut ev = Evaluator::new(&mut callback);
    circuit(&mut ev);
    let output = ev.decode_output();
    for x in output {
        print!("{} ", x);
    }
    println!();
    Ok(())
}
