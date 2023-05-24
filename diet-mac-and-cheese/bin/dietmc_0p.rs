mod cli;

use clap::Parser;
use cli::{Cli, LpnSize, Prover::*};
use diet_mac_and_cheese::backend_multifield::{
    CircInputs, EvaluatorCirc, FieldOrPluginType, Party,
};
use diet_mac_and_cheese::read_sieveir_phase2::{
    read_private_inputs, read_public_inputs, read_types,
};
use diet_mac_and_cheese::text_reader::number_to_bytes;
use log::info;
use mac_n_cheese_sieve_parser::text_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_sieve_parser::RelationReader as RR;
use mac_n_cheese_sieve_parser::ValueStreamReader as VSR;
use mac_n_cheese_sieve_parser::{Type, ValueStreamKind};
use pretty_env_logger;
use scuttlebutt::{AesRng, Channel};
use std::collections::VecDeque;
use std::env;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Instant;

// Transform a path that could be either a file or a directory containing files into a vector of filenames.
// Passing `/dev/null` returns an empty vector.
fn path_to_files(p: PathBuf) -> Vec<PathBuf> {
    if p.is_file() {
        return vec![p];
    }

    if p.is_dir() {
        let paths = p
            .read_dir()
            .unwrap_or_else(|_| panic!("Error reading directory {:?}", p));

        let mut r = vec![];
        for path in paths {
            r.push(
                path.unwrap_or_else(|_| panic!("error reading dir path"))
                    .path(),
            );
        }
        r.sort();
        return r;
    }

    // This allows to pass `/dev/null` and return an empty vector
    return vec![];
}

// Run with with relation in text format
fn run_text(args: &Cli) -> std::io::Result<()> {
    let witness_path;
    if args.command.is_some() {
        match args.command.as_ref().unwrap() {
            Prover { witness } => {
                witness_path = witness.to_path_buf();
            }
        }
        info!("witness: {:?}", witness_path);
    } else {
        witness_path = PathBuf::new();
    }
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

    let start = Instant::now();
    let mut inputs = CircInputs::default();

    let instance_paths = path_to_files(instance_path);
    for (i, instance_path) in instance_paths.iter().enumerate() {
        let mut instances = VecDeque::new();
        let mut stream_inp =
            ValueStreamReader::open(ValueStreamKind::Public, instance_path.as_path()).unwrap();

        loop {
            let n = stream_inp.next().unwrap();
            match n {
                None => {
                    break;
                }
                Some(v) => instances.push_back(number_to_bytes(&v)),
            }
        }
        let field = stream_inp.modulus();
        inputs.ingest_instances(i, instances);
        info!(
            "Loaded idx:{:?} field:{:?} file:{:?} num public instances:{:?}",
            i,
            number_to_bytes(&field),
            instance_path,
            inputs.ins[i].len()
        );
    }

    if args.command.is_some() {
        // PROVER
        let witness_paths = path_to_files(witness_path);
        for (i, witness_path) in witness_paths.iter().enumerate() {
            let mut witnesses = VecDeque::new();
            let mut stream_wit =
                ValueStreamReader::open(ValueStreamKind::Private, witness_path.as_path()).unwrap();

            loop {
                let n = stream_wit.next().unwrap();
                match n {
                    None => {
                        break;
                    }
                    Some(v) => witnesses.push_back(number_to_bytes(&v)),
                }
            }
            let field = stream_wit.modulus();
            inputs.ingest_witnesses(i, witnesses);
            info!(
                "Loaded idx:{:?} field:{:?} file:{:?} num public instances:{:?}",
                i,
                number_to_bytes(&field),
                witness_path,
                inputs.wit[i].len()
            );
        }
    }

    let rel = RelationReader::open(relation_path.clone().as_path()).unwrap();

    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    if args.command.is_none() {
        // Verifier mode
        let start = Instant::now();
        info!("time eval builder: {:?}", start.elapsed());

        let listener = TcpListener::bind(args.connection_addr.clone())?;
        match listener.accept() {
            Ok((stream, _addr)) => {
                info!("connection received");
                let reader = BufReader::new(stream.try_clone().unwrap());
                let writer = BufWriter::new(stream);
                let mut channel = Channel::new(reader, writer);

                let start = Instant::now();
                let mut rng = AesRng::new();

                let mut evaluator =
                    EvaluatorCirc::new(Party::Verifier, &mut channel, &mut rng, inputs, false)
                        .unwrap();
                for (idx, f) in rel.header().types.iter().enumerate() {
                    match f {
                        Type::Field { modulus: fi } => {
                            let rng = AesRng::new();
                            let rng2 = AesRng::new();
                            evaluator
                                .load_backend(
                                    &mut channel,
                                    rng,
                                    rng2,
                                    &number_to_bytes(&fi),
                                    idx,
                                    args.lpn == LpnSize::Small,
                                    args.nobatching,
                                )
                                .unwrap();
                        }
                        _ => {
                            todo!("Type not supported yet: {:?}", f);
                        }
                    }
                }
                info!("init time: {:?}", start.elapsed());

                let start = Instant::now();
                evaluator.evaluate_relation_text(&relation_path).unwrap();
                info!("time circ exec: {:?}", start.elapsed());
                info!("VERIFIER DONE!");
            }
            Err(e) => info!("couldn't get client: {:?}", e),
        }
    } else {
        // Prover mode
        let start = Instant::now();
        info!("time eval builder: {:?}", start.elapsed());

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
        let reader = BufReader::new(stream.try_clone().unwrap());
        let writer = BufWriter::new(stream);
        let mut channel = Channel::new(reader, writer);

        let start = Instant::now();
        let mut rng = AesRng::new();

        let mut evaluator =
            EvaluatorCirc::new(Party::Prover, &mut channel, &mut rng, inputs, false).unwrap();
        for (idx, f) in rel.header().types.iter().enumerate() {
            match f {
                Type::Field { modulus: fi } => {
                    let rng = AesRng::new();
                    let rng2 = AesRng::new();
                    evaluator
                        .load_backend(
                            &mut channel,
                            rng,
                            rng2,
                            &number_to_bytes(&fi),
                            idx,
                            args.lpn == LpnSize::Small,
                            args.nobatching,
                        )
                        .unwrap();
                }
                _ => {
                    todo!("Type not supported yet: {:?}", f);
                }
            }
        }
        info!("init time: {:?}", start.elapsed());
        let start = Instant::now();
        evaluator.evaluate_relation_text(&relation_path).unwrap();
        info!("time circ exec: {:?}", start.elapsed());
    }
    Ok(())
}

fn run(args: &Cli) -> std::io::Result<()> {
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
        return run_text(args);
    }

    let witness_path;
    if args.command.is_some() {
        match args.command.as_ref().unwrap() {
            Prover { witness } => {
                witness_path = witness.to_path_buf();
            }
        }
        info!("witness: {:?}", witness_path);
    } else {
        witness_path = PathBuf::new();
    }
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

    let fields = read_types(&args.relation).unwrap();
    let start = Instant::now();
    let mut inputs = CircInputs::default();

    let instance_paths = path_to_files(instance_path);
    for (i, instance_path) in instance_paths.iter().enumerate() {
        let mut instances = VecDeque::new();
        let field = read_public_inputs(&instance_path, &mut instances);
        inputs.ingest_instances(i, instances);
        info!(
            "Loaded idx:{:?} field:{:?} file:{:?} num public instances:{:?}",
            i,
            field,
            instance_path,
            inputs.ins[i].len()
        );
    }

    if args.command.is_some() {
        // PROVER
        let witness_paths = path_to_files(witness_path);
        for (i, witness_path) in witness_paths.iter().enumerate() {
            let mut witnesses = VecDeque::new();
            let field = read_private_inputs(&witness_path, &mut witnesses);
            inputs.ingest_witnesses(i, witnesses);
            info!(
                "Loaded idx:{:?} field:{:?} file:{:?} num private witnesses:{:?}",
                i,
                field,
                witness_path,
                inputs.wit[i].len()
            );
        }
    }

    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    if args.command.is_none() {
        // Verifier mode
        let start = Instant::now();
        info!("time eval builder: {:?}", start.elapsed());

        let listener = TcpListener::bind(args.connection_addr.clone())?;
        match listener.accept() {
            Ok((stream, _addr)) => {
                info!("connection received");
                let reader = BufReader::new(stream.try_clone().unwrap());
                let writer = BufWriter::new(stream);
                let mut channel = Channel::new(reader, writer);

                let start = Instant::now();
                let mut rng = AesRng::new();

                let mut evaluator =
                    EvaluatorCirc::new(Party::Verifier, &mut channel, &mut rng, inputs, false)
                        .unwrap();
                for (idx, f) in fields.0.iter().enumerate() {
                    match &f.1 {
                        FieldOrPluginType::Field(fi) => {
                            let rng = AesRng::new();
                            let rng2 = AesRng::new();
                            evaluator
                                .load_backend(
                                    &mut channel,
                                    rng,
                                    rng2,
                                    fi.as_slice(),
                                    idx,
                                    args.lpn == LpnSize::Small,
                                    args.nobatching,
                                )
                                .unwrap();
                        }
                        _ => {
                            todo!("Type not supported yet: {:?}", f);
                        }
                    }
                }
                info!("init time: {:?}", start.elapsed());

                let start = Instant::now();
                evaluator.evaluate_relation(&relation_path).unwrap();
                info!("time circ exec: {:?}", start.elapsed());
                info!("VERIFIER DONE!");
            }
            Err(e) => info!("couldn't get client: {:?}", e),
        }
    } else {
        // Prover mode
        let start = Instant::now();
        info!("time eval builder: {:?}", start.elapsed());

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
        let reader = BufReader::new(stream.try_clone().unwrap());
        let writer = BufWriter::new(stream);
        let mut channel = Channel::new(reader, writer);

        let start = Instant::now();
        let mut rng = AesRng::new();

        let mut evaluator =
            EvaluatorCirc::new(Party::Prover, &mut channel, &mut rng, inputs, false).unwrap();
        for (idx, f) in fields.0.iter().enumerate() {
            match &f.1 {
                FieldOrPluginType::Field(fi) => {
                    let rng = AesRng::new();
                    let rng2 = AesRng::new();
                    evaluator
                        .load_backend(
                            &mut channel,
                            rng,
                            rng2,
                            fi.as_slice(),
                            idx,
                            args.lpn == LpnSize::Small,
                            args.nobatching,
                        )
                        .unwrap();
                }
                _ => {
                    todo!("Type not supported yet: {:?}", f);
                }
            }
        }
        info!("init time: {:?}", start.elapsed());
        let start = Instant::now();
        evaluator.evaluate_relation(&relation_path).unwrap();
        info!("time circ exec: {:?}", start.elapsed());
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    // if log-level `RUST_LOG` not already set, then set to info
    match env::var("RUST_LOG") {
        Ok(val) => println!("loglvl: {}", val),
        Err(_) => env::set_var("RUST_LOG", "info"),
    };

    pretty_env_logger::init_timed();

    let cli = Cli::parse();

    run(&cli)
}
