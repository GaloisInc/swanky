#![feature(test)]

pub mod comm;

use clap::{App, Arg, ErrorKind, SubCommand};
use failure::Error;
use fancy_garbling::fancy::{Fancy, HasModulus};
use fancy_garbling::garble::{Evaluator, Garbler, GateType, Message};
use fancy_garbling::wire::Wire;
use ocelot::base::dummy::DummyOT;
use ocelot::base::{bitvec_to_u128, u128_to_bitvec, ObliviousTransfer};
use ocelot::otext::iknp::IKNP;
use ocelot::otext::OTExtension;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

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
                Ok(stream) => garble(stream, &input),
                Err(e) => Err(e),
            },
            (None, Some(f)) => match garbler_file(f) {
                Ok(stream) => garble(stream, &input),
                Err(e) => Err(e),
            },
            (_, _) => unreachable!(),
        }
    } else if let Some(_) = matches.subcommand_matches("evaluator") {
        let input = vec![1];
        match (host, file) {
            (None, None) => Err(failure::err_msg("One of --host or --file must be used")),
            (Some(h), None) => match evaluator_tcp(h) {
                Ok(stream) => evaluate(stream, &input),
                Err(e) => Err(e),
            },
            (None, Some(f)) => match evaluator_file(f) {
                Ok(stream) => evaluate(stream, &input),
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
    let b = f.evaluator_input(None, q);
    let a = f.garbler_input(None, q);
    let c = f.add(&a, &b);
    f.output(None, &c);
}

fn garbler_file(file: &str) -> Result<impl Read + Write, Error> {
    println!("Creating file '{}'...", file);
    let f = fs::File::create(file)?;
    Ok(f)
}

fn garbler_tcp(host: &str) -> Result<impl Read + Write, Error> {
    println!("Launching server on '{}'...", host);
    let server = TcpListener::bind(host)?;
    println!("Success!");
    for stream in server.incoming() {
        let stream = stream?;
        return Ok(stream);
    }
    return Err(failure::err_msg("Unable to connect to stream"));
}

fn garble<S>(stream: S, input: &[u16]) -> Result<(), Error>
where
    S: Read + Write + Send + 'static,
{
    let mut input = input.to_vec().into_iter();
    let stream = Arc::new(Mutex::new(stream));
    let callback = move |msg: Message| {
        let m = match msg {
            Message::UnencodedGarblerInput { zero, delta } => {
                Message::GarblerInput(zero.plus(&delta.cmul(input.next().unwrap())))
            }
            Message::UnencodedEvaluatorInput { zero, delta } => {
                let mut ot = DummyOT::new(stream.clone());
                ot.send((
                    &u128_to_bitvec(zero.as_u128()),
                    &u128_to_bitvec(zero.plus(&delta).as_u128()),
                ))
                .unwrap();
                return ();
            }
            m => m,
        };
        let mut stream = stream.lock().unwrap();
        comm::send(&mut *stream, &m.to_bytes()).expect("Unable to send message");
    };
    let mut gb = Garbler::new(callback);
    circuit(&mut gb);
    Ok(())
}

fn evaluator_file(file: &str) -> Result<impl Read + Write, Error> {
    println!("Opening file '{}'...", file);
    let f = fs::File::open(file)?;
    Ok(f)
}

fn evaluator_tcp(host: &str) -> Result<impl Read + Write, Error> {
    println!("Connecting to server on '{}'...", host);
    let stream = TcpStream::connect(host)?;
    Ok(stream)
}

fn evaluate<S>(stream: S, input: &[u16]) -> Result<(), Error>
where
    S: Read + Write + Send + 'static,
{
    let stream = Arc::new(Mutex::new(stream));
    let _input = input.into_iter();
    let callback = move |gate| {
        let bv = match gate {
            GateType::EvaluatorInput { modulus } => {
                let mut ot = DummyOT::new(stream.clone());
                let wire = ot.receive(false, 128).unwrap();
                Message::EvaluatorInput(Wire::from_u128(bitvec_to_u128(&wire), modulus))
            }
            GateType::Other => {
                let mut stream = stream.lock().unwrap();
                let bytes = comm::receive(&mut *stream).expect("Failed to receive message");
                let msg = Message::from_bytes(&bytes).expect("Failed to convert bytes to message");
                msg
            }
        };
        bv
    };
    let mut ev = Evaluator::new(callback);
    circuit(&mut ev);
    let output = ev.decode_output();
    for x in output {
        print!("{} ", x);
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test() {
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        std::thread::spawn(move || {
            garble(sender, &[0]).unwrap();
        });
        evaluate(receiver, &[0]).unwrap();
    }
}
