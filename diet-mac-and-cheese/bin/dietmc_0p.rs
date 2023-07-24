mod cli;

use clap::Parser;
use cli::{Cli, LpnSize, Prover::*};
use diet_mac_and_cheese::backend_multifield::{EvaluatorCirc, Party};
use diet_mac_and_cheese::circuit_ir::{CircInputs, TypeStore};
use diet_mac_and_cheese::read_sieveir_phase2::{
    read_private_inputs, read_public_inputs, read_types,
};
use diet_mac_and_cheese::text_reader::number_to_bytes;
use eyre::{Result, WrapErr};
use log::info;
use mac_n_cheese_sieve_parser::text_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_sieve_parser::RelationReader as RR;
use mac_n_cheese_sieve_parser::ValueStreamKind;
use mac_n_cheese_sieve_parser::ValueStreamReader as VSR;
use pretty_env_logger;
use scuttlebutt::{AesRng, Channel};
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Instant;

// Transform a path that could be either a file or a directory containing files into a vector of filenames.
// Passing `/dev/null` returns an empty vector.
fn path_to_files(path: PathBuf) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        Ok(vec![path])
    } else if path.is_dir() {
        let paths = path
            .read_dir()
            .wrap_err_with(|| format!("Error reading directory {path:?}"))?;

        let mut files: Vec<PathBuf> = vec![];
        for path in paths {
            files.push(
                path.wrap_err_with(|| format!("error reading dir path"))?
                    .path(),
            );
        }
        files.sort();
        Ok(files)
    } else {
        // This allows to pass `/dev/null` and return an empty vector
        Ok(vec![])
    }
}

// Run with relation in text format
fn run_text(args: &Cli) -> Result<()> {
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

    let start = Instant::now();
    let mut inputs = CircInputs::default();

    let instance_paths = path_to_files(instance_path)?;
    for (i, instance_path) in instance_paths.iter().enumerate() {
        let mut instances = VecDeque::new();
        let mut stream_inp =
            ValueStreamReader::open(ValueStreamKind::Public, instance_path.as_path())?;

        while let Some(v) = stream_inp.next()? {
            instances.push_back(v);
        }
        let field = stream_inp.modulus();
        let ninstances = instances.len();
        inputs.ingest_instances(i, instances);
        info!(
            "Loaded idx:{:?} field:{:?} file:{:?} num public instances:{:?}",
            i,
            number_to_bytes(&field),
            instance_path,
            ninstances
        );
    }

    if let Some(Prover { witness }) = &args.command {
        // Prover mode
        info!("witness: {:?}", witness);
        let witness_paths = path_to_files(witness.to_path_buf())?;
        for (i, witness_path) in witness_paths.iter().enumerate() {
            let mut witnesses = VecDeque::new();
            let mut stream_wit =
                ValueStreamReader::open(ValueStreamKind::Private, witness_path.as_path())?;

            while let Some(v) = stream_wit.next()? {
                witnesses.push_back(v);
            }
            let field = stream_wit.modulus();
            let nwitnesses = witnesses.len();
            inputs.ingest_witnesses(i, witnesses);
            info!(
                "Loaded idx:{:?} field:{:?} file:{:?} num public instances:{:?}",
                i,
                number_to_bytes(&field),
                witness_path,
                nwitnesses
            );
        }
    }

    let rel = RelationReader::open(relation_path.as_path())?;

    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    match args.command {
        None => {
            // Verifier mode
            let listener = TcpListener::bind(&args.connection_addr)?;
            match listener.accept() {
                Ok((stream, _addr)) => {
                    info!("connection received");
                    let reader = BufReader::new(stream.try_clone()?);
                    let writer = BufWriter::new(stream);
                    let mut channel = Channel::new(reader, writer);

                    let start = Instant::now();
                    let rng = AesRng::new();

                    let mut evaluator = EvaluatorCirc::new(
                        Party::Verifier,
                        &mut channel,
                        rng,
                        inputs,
                        TypeStore::try_from(rel.header().types.clone())?,
                        false,
                        args.nobatching,
                    )?;
                    evaluator.load_backends(&mut channel, args.lpn == LpnSize::Small)?;
                    info!("init time: {:?}", start.elapsed());

                    let start = Instant::now();
                    let relation_file = File::open(relation_path)?;
                    let relation_reader = BufReader::new(relation_file);
                    evaluator.evaluate_relation_text(relation_reader)?;
                    info!("time circ exec: {:?}", start.elapsed());
                    info!("VERIFIER DONE!");
                }
                Err(e) => info!("couldn't get client: {:?}", e),
            }
        }
        Some(Prover { witness: _ }) => {
            // Prover mode
            let stream;
            loop {
                let c = TcpStream::connect(args.connection_addr.clone());
                match c {
                    Ok(s) => {
                        stream = s;
                        break;
                    }
                    Err(_) => {}
                }
            }
            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator = EvaluatorCirc::new(
                Party::Prover,
                &mut channel,
                rng,
                inputs,
                TypeStore::try_from(rel.header().types.clone())?,
                false,
                args.nobatching,
            )?;
            evaluator.load_backends(&mut channel, args.lpn == LpnSize::Small)?;
            info!("init time: {:?}", start.elapsed());
            let start = Instant::now();
            let relation_file = File::open(relation_path)?;
            let relation_reader = BufReader::new(relation_file);
            evaluator.evaluate_relation_text(relation_reader)?;
            info!("time circ exec: {:?}", start.elapsed());
            info!("PROVER DONE!");
        }
    }
    Ok(())
}

// Run with relation in flatbuffers format
fn run_flatbuffers(args: &Cli) -> Result<()> {
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

    let fields = read_types(&args.relation).unwrap();
    let start = Instant::now();
    let mut inputs = CircInputs::default();

    let instance_paths = path_to_files(instance_path)?;
    for (i, instance_path) in instance_paths.iter().enumerate() {
        let mut instances = VecDeque::new();
        let field = read_public_inputs(&instance_path, &mut instances);
        let ninstances = instances.len();
        inputs.ingest_instances(i, instances);
        info!(
            "Loaded idx:{:?} field:{:?} file:{:?} num public instances:{:?}",
            i, field, instance_path, ninstances
        );
    }

    if let Some(Prover { witness }) = &args.command {
        // Prover mode
        info!("witness: {:?}", witness);
        let witness_paths = path_to_files(witness.to_path_buf())?;
        for (i, witness_path) in witness_paths.iter().enumerate() {
            let mut witnesses = VecDeque::new();
            let field = read_private_inputs(&witness_path, &mut witnesses);
            let nwitnesses = witnesses.len();
            inputs.ingest_witnesses(i, witnesses);
            info!(
                "Loaded idx:{:?} field:{:?} file:{:?} num private witnesses:{:?}",
                i, field, witness_path, nwitnesses,
            );
        }
    }

    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    match args.command {
        None => {
            // Verifier mode
            let listener = TcpListener::bind(args.connection_addr.clone())?;
            match listener.accept() {
                Ok((stream, _addr)) => {
                    info!("connection received");
                    let reader = BufReader::new(stream.try_clone()?);
                    let writer = BufWriter::new(stream);
                    let mut channel = Channel::new(reader, writer);

                    let start = Instant::now();
                    let rng = AesRng::new();

                    let mut evaluator = EvaluatorCirc::new(
                        Party::Verifier,
                        &mut channel,
                        rng,
                        inputs,
                        fields,
                        false,
                        args.nobatching,
                    )?;
                    evaluator.load_backends(&mut channel, args.lpn == LpnSize::Small)?;
                    info!("init time: {:?}", start.elapsed());

                    let start = Instant::now();
                    evaluator.evaluate_relation(&relation_path).unwrap();
                    info!("time circ exec: {:?}", start.elapsed());
                    info!("VERIFIER DONE!");
                }
                Err(e) => info!("couldn't get client: {:?}", e),
            }
        }
        Some(Prover { witness: _ }) => {
            // Prover mode
            let stream;
            loop {
                let c = TcpStream::connect(args.connection_addr.clone());
                match c {
                    Ok(s) => {
                        stream = s;
                        break;
                    }
                    Err(_) => {}
                }
            }
            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator = EvaluatorCirc::new(
                Party::Prover,
                &mut channel,
                rng,
                inputs,
                fields.clone(),
                false,
                args.nobatching,
            )?;
            evaluator.load_backends(&mut channel, args.lpn == LpnSize::Small)?;
            info!("init time: {:?}", start.elapsed());
            let start = Instant::now();
            evaluator.evaluate_relation(&relation_path)?;
            info!("time circ exec: {:?}", start.elapsed());
        }
    }
    Ok(())
}

fn run(args: &Cli) -> Result<()> {
    if args.command.is_some() {
        info!("prover mode");
    } else {
        info!("verifier mode");
    }
    info!("addr: {:?}", args.connection_addr);
    info!("lpn: {:?}", args.lpn);
    info!("instance: {:?}", args.instance);
    info!("text format: {:?}", args.text);

    if args.text {
        run_text(args)
    } else {
        run_flatbuffers(args)
    }
}

fn main() -> Result<()> {
    // if log-level `RUST_LOG` not already set, then set to info
    match env::var("RUST_LOG") {
        Ok(val) => println!("loglvl: {}", val),
        Err(_) => env::set_var("RUST_LOG", "info"),
    };

    pretty_env_logger::init_timed();

    let cli = Cli::parse();

    run(&cli)
}
