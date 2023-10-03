mod cli;

use clap::Parser;
use cli::{Cli, LpnSize};
use diet_mac_and_cheese::backend_multifield::EvaluatorCirc;
use diet_mac_and_cheese::backend_trait::Party;
use diet_mac_and_cheese::circuit_ir::{CircInputs, TypeStore};
use diet_mac_and_cheese::read_sieveir_phase2::{
    read_private_inputs, read_public_inputs, read_types,
};
use diet_mac_and_cheese::svole_thread::SvoleAtomic;
use diet_mac_and_cheese::svole_trait::{SvoleReceiver, SvoleSender};
use eyre::{bail, Result, WrapErr};
use log::info;
use mac_n_cheese_sieve_parser::text_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_sieve_parser::RelationReader as RR;
use mac_n_cheese_sieve_parser::ValueStreamKind;
use mac_n_cheese_sieve_parser::ValueStreamReader as VSR;
use pretty_env_logger;
use scuttlebutt::field::{F40b, F2};
use scuttlebutt::{AesRng, Channel, SyncChannel};
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Instant;

use jemallocator::Jemalloc;

use crate::cli::Config;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

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

fn start_connection_verifier(addresses: &[String]) -> Result<Vec<TcpStream>> {
    let mut tcp_streams = vec![];

    for addr in addresses.iter() {
        let listener = TcpListener::bind(addr.clone())?;
        if let Ok((stream, _addr)) = listener.accept() {
            tcp_streams.push(stream);
            info!("accept connections on {:?}", addr);
        } else {
            bail!("Error binding addr: {:?}", addr);
        }
    }

    Ok(tcp_streams)
}

fn start_connection_prover(addresses: &[String]) -> Result<Vec<TcpStream>> {
    let mut tcp_streams = vec![];

    for addr in addresses.iter() {
        loop {
            let c = TcpStream::connect(addr.clone());
            if let Ok(stream) = c {
                tcp_streams.push(stream);
                info!("connection accepted on {:?}", addr);
                break;
            }
        }
    }

    Ok(tcp_streams)
}

fn build_inputs_types_text(args: &Cli) -> Result<(CircInputs, TypeStore)> {
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

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
            i, field, instance_path, ninstances
        );
    }

    if let Some(witness) = &args.witness {
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
                i, field, witness_path, nwitnesses
            );
        }
    }

    let rel = RelationReader::open(relation_path.as_path())?;
    Ok((inputs, TypeStore::try_from(rel.header().types.clone())?))
}

fn build_inputs_flatbuffers(args: &Cli) -> Result<(CircInputs, TypeStore)> {
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();

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

    if let Some(witness) = &args.witness {
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
    Ok((inputs, fields))
}

// Run with relation in text format
fn run_text(args: &Cli, config: &Config) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = build_inputs_types_text(args)?;
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            // Verifier mode
            let mut conns = start_connection_verifier(&vec![args.connection_addr.clone()])?;
            let stream = conns.pop().unwrap();

            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator =
                EvaluatorCirc::<_, SvoleSender<F40b>, SvoleReceiver<F2, F40b>>::new(
                    Party::Verifier,
                    &mut channel,
                    rng,
                    inputs,
                    type_store,
                    config.lpn() == LpnSize::Small,
                    config.no_batching(),
                )?;
            evaluator.load_backends::<SvoleSender<F40b>, SvoleReceiver<F40b, F40b>>(
                &mut channel,
                config.lpn() == LpnSize::Small,
            )?;
            info!("init time: {:?}", start.elapsed());

            let start = Instant::now();
            let relation_file = File::open(relation_path)?;
            let relation_reader = BufReader::new(relation_file);
            evaluator.evaluate_relation_text(relation_reader)?;
            info!("time circ exec: {:?}", start.elapsed());
            info!("VERIFIER DONE!");
        }
        Some(_) => {
            // Prover mode
            let mut conns = start_connection_prover(&vec![args.connection_addr.clone()])?;
            let stream = conns.pop().unwrap();

            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator =
                EvaluatorCirc::<_, SvoleSender<F40b>, SvoleReceiver<F2, F40b>>::new(
                    Party::Prover,
                    &mut channel,
                    rng,
                    inputs,
                    type_store,
                    config.lpn() == LpnSize::Small,
                    config.no_batching(),
                )?;
            evaluator.load_backends::<SvoleSender<F40b>, SvoleReceiver<F40b, F40b>>(
                &mut channel,
                config.lpn() == LpnSize::Small,
            )?;
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
fn run_text_multihtreaded(args: &Cli, config: &Config) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = build_inputs_types_text(args)?;
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let addresses: Vec<String> = parse_addresses(args, config);

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            // Verifier mode
            let mut conns = start_connection_verifier(&addresses)?;

            let init_time = Instant::now();
            let total_time = Instant::now();

            let rng = AesRng::new();

            let conn = conns.pop().unwrap();
            let reader = BufReader::new(conn.try_clone()?);
            let writer = BufWriter::new(conn);
            let channel_f2_svole = SyncChannel::new(reader, writer);

            let mut handles = vec![];
            let (mut evaluator, handle_f2) =
                EvaluatorCirc::<_, SvoleAtomic<(F2, F40b)>, SvoleAtomic<F40b>>::new_multithreaded(
                    Party::Verifier,
                    channel_f2_svole,
                    rng,
                    inputs,
                    type_store,
                    config.no_batching(),
                    config.lpn() == LpnSize::Small,
                )?;
            handles.push(handle_f2);

            let mut channels_svole = vec![];
            for _ in 1..conns.len() {
                let conn = conns.pop().unwrap();
                let reader = BufReader::new(conn.try_clone()?);
                let writer = BufWriter::new(conn);
                channels_svole.push(SyncChannel::new(reader, writer));
            }
            //eyre::ensure!(conns.len() == 1);
            let conn_main = conns.pop().unwrap();
            let reader = BufReader::new(conn_main.try_clone()?);
            let writer = BufWriter::new(conn_main);
            let mut channel = Channel::new(reader, writer);

            let handles_fields = evaluator.load_backends_multithreaded(
                &mut channel,
                channels_svole,
                config.lpn() == LpnSize::Small,
            )?;
            handles.extend(handles_fields);
            info!("init time: {:?}", init_time.elapsed());

            let start = Instant::now();
            let relation_file = File::open(relation_path)?;
            let relation_reader = BufReader::new(relation_file);
            evaluator.evaluate_relation_text(relation_reader)?;
            evaluator.terminate()?;
            for handle in handles {
                handle.join().unwrap();
            }
            info!("circ exec time: {:?}", start.elapsed());

            info!("total time: {:?}", total_time.elapsed());
            info!("VERIFIER DONE!");
        }
        Some(_) => {
            // Prover mode
            let mut conns = start_connection_prover(&addresses)?;

            let init_time = Instant::now();
            let total_time = Instant::now();

            let rng = AesRng::new();

            let conn = conns.pop().unwrap();
            let reader = BufReader::new(conn.try_clone()?);
            let writer = BufWriter::new(conn);
            let channel_f2_svole = SyncChannel::new(reader, writer);

            let mut handles = vec![];
            let (mut evaluator, handle_f2) =
                EvaluatorCirc::<_, SvoleAtomic<(F2, F40b)>, SvoleAtomic<F40b>>::new_multithreaded(
                    Party::Prover,
                    channel_f2_svole,
                    rng,
                    inputs,
                    type_store,
                    config.no_batching(),
                    config.lpn() == LpnSize::Small,
                )?;
            handles.push(handle_f2);

            let mut channels_svole = vec![];
            for _ in 1..conns.len() {
                let conn = conns.pop().unwrap();
                let reader = BufReader::new(conn.try_clone()?);
                let writer = BufWriter::new(conn);
                channels_svole.push(SyncChannel::new(reader, writer));
            }
            //eyre::ensure!(conns.len() == 1);
            let conn_main = conns.pop().unwrap();
            let reader = BufReader::new(conn_main.try_clone()?);
            let writer = BufWriter::new(conn_main);
            let mut channel = Channel::new(reader, writer);

            let handles_fields = evaluator.load_backends_multithreaded(
                &mut channel,
                channels_svole,
                config.lpn() == LpnSize::Small,
            )?;
            handles.extend(handles_fields);
            info!("init time: {:?}", init_time.elapsed());

            let start = Instant::now();
            let relation_file = File::open(relation_path)?;
            let relation_reader = BufReader::new(relation_file);
            evaluator.evaluate_relation_text(relation_reader)?;
            evaluator.terminate()?;
            for handle in handles {
                handle.join().unwrap();
            }
            info!("circ exec time: {:?}", start.elapsed());

            info!("total time: {:?}", total_time.elapsed());
            info!("PROVER DONE!");
        }
    }
    Ok(())
}

// Run with relation in flatbuffers format
fn run_flatbuffers(args: &Cli, config: &Config) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = build_inputs_flatbuffers(args)?;
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            // Verifier mode
            let mut conns = start_connection_verifier(&vec![args.connection_addr.clone()])?;
            let stream = conns.pop().unwrap();

            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator =
                EvaluatorCirc::<_, SvoleSender<F40b>, SvoleReceiver<F2, F40b>>::new(
                    Party::Verifier,
                    &mut channel,
                    rng,
                    inputs,
                    type_store,
                    config.lpn() == LpnSize::Small,
                    config.no_batching(),
                )?;
            evaluator.load_backends::<SvoleSender<F40b>, SvoleReceiver<F40b, F40b>>(
                &mut channel,
                config.lpn() == LpnSize::Small,
            )?;
            info!("init time: {:?}", start.elapsed());

            let start = Instant::now();
            evaluator.evaluate_relation(&relation_path).unwrap();
            info!("time circ exec: {:?}", start.elapsed());
            info!("VERIFIER DONE!");
        }
        Some(_) => {
            // Prover mode
            let mut conns = start_connection_prover(&vec![args.connection_addr.clone()])?;
            let stream = conns.pop().unwrap();

            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator =
                EvaluatorCirc::<_, SvoleSender<F40b>, SvoleReceiver<F2, F40b>>::new(
                    Party::Prover,
                    &mut channel,
                    rng,
                    inputs,
                    type_store,
                    config.lpn() == LpnSize::Small,
                    config.no_batching(),
                )?;
            evaluator.load_backends::<SvoleSender<F40b>, SvoleReceiver<F40b, F40b>>(
                &mut channel,
                config.lpn() == LpnSize::Small,
            )?;
            info!("init time: {:?}", start.elapsed());
            let start = Instant::now();
            evaluator.evaluate_relation(&relation_path)?;
            info!("time circ exec: {:?}", start.elapsed());
        }
    }
    Ok(())
}

fn parse_addresses(args: &Cli, config: &Config) -> Vec<String> {
    let mut addresses: Vec<String> = args
        .connection_addr
        .clone()
        .split(",")
        .map(|x| x.into())
        .collect();
    // if there are not enough addresses then add some other ones
    if addresses.len() == 1 {
        let split_addr: Vec<String> = addresses[0].clone().split(":").map(|x| x.into()).collect();
        let addr = split_addr[0].clone();
        let port: usize = split_addr[1]
            .clone()
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("cant parse port"));
        for i in 1..config.threads() {
            let mut new_addr = addr.clone();
            new_addr.push_str(":".into());
            let new_port = format!("{:?}", port + i);
            new_addr.push_str(&new_port);
            addresses.push(new_addr);
        }
    }
    addresses
}

// Run with relation in flatbuffers format
fn run_flatbuffers_multihtreaded(args: &Cli, config: &Config) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = build_inputs_flatbuffers(args)?;
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let addresses: Vec<String> = parse_addresses(args, config);

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            // Verifier mode
            let mut conns = start_connection_verifier(&addresses)?;

            let init_time = Instant::now();
            let total_time = Instant::now();

            let conn = conns.pop().unwrap();
            let reader = BufReader::new(conn.try_clone()?);
            let writer = BufWriter::new(conn);
            let channel_f2_svole = SyncChannel::new(reader, writer);

            let rng = AesRng::new();

            let mut handles = vec![];
            let (mut evaluator, handle_f2) =
                EvaluatorCirc::<_, SvoleAtomic<(F2, F40b)>, SvoleAtomic<F40b>>::new_multithreaded(
                    Party::Verifier,
                    channel_f2_svole,
                    rng,
                    inputs,
                    type_store,
                    config.no_batching(),
                    config.lpn() == LpnSize::Small,
                )?;
            handles.push(handle_f2);

            let mut channels_svole = vec![];
            for _ in 1..conns.len() {
                let conn = conns.pop().unwrap();
                let reader = BufReader::new(conn.try_clone()?);
                let writer = BufWriter::new(conn);
                channels_svole.push(SyncChannel::new(reader, writer));
            }
            //eyre::ensure!(conns.len() == 1);
            let conn_main = conns.pop().unwrap();
            let reader = BufReader::new(conn_main.try_clone()?);
            let writer = BufWriter::new(conn_main);
            let mut channel = Channel::new(reader, writer);

            let handles_fields = evaluator.load_backends_multithreaded(
                &mut channel,
                channels_svole,
                config.lpn() == LpnSize::Small,
            )?;
            handles.extend(handles_fields);
            info!("init time: {:?}", init_time.elapsed());

            let start = Instant::now();
            evaluator.evaluate_relation(&relation_path).unwrap();
            evaluator.terminate()?;
            for handle in handles {
                handle.join().unwrap();
            }
            info!("circ exec time: {:?}", start.elapsed());

            info!("total time: {:?}", total_time.elapsed());
            info!("VERIFIER DONE!");
        }
        Some(_) => {
            // Prover mode
            let mut conns = start_connection_prover(&addresses)?;

            let init_time = Instant::now();
            let total_time = Instant::now();

            let conn = conns.pop().unwrap();
            let reader = BufReader::new(conn.try_clone()?);
            let writer = BufWriter::new(conn);
            let channel_f2_svole = SyncChannel::new(reader, writer);

            let rng = AesRng::new();
            let mut handles = vec![];
            let (mut evaluator, handle_f2) =
                EvaluatorCirc::<_, SvoleAtomic<(F2, F40b)>, SvoleAtomic<F40b>>::new_multithreaded(
                    Party::Prover,
                    channel_f2_svole,
                    rng,
                    inputs,
                    type_store,
                    config.no_batching(),
                    config.lpn() == LpnSize::Small,
                )?;
            handles.push(handle_f2);

            let mut channels_svole = vec![];
            for _ in 1..conns.len() {
                let conn = conns.pop().unwrap();
                let reader = BufReader::new(conn.try_clone()?);
                let writer = BufWriter::new(conn);
                channels_svole.push(SyncChannel::new(reader, writer));
            }
            //eyre::ensure!(conns.len() == 1);
            let conn_main = conns.pop().unwrap();
            let reader = BufReader::new(conn_main.try_clone()?);
            let writer = BufWriter::new(conn_main);
            let mut channel = Channel::new(reader, writer);

            let handles_fields = evaluator.load_backends_multithreaded(
                &mut channel,
                channels_svole,
                config.lpn() == LpnSize::Small,
            )?;
            handles.extend(handles_fields);

            info!("init time: {:?}", init_time.elapsed());
            let start = Instant::now();
            evaluator.evaluate_relation(&relation_path)?;
            evaluator.terminate()?;
            for handle in handles {
                handle.join().unwrap();
            }
            info!("circ exec time: {:?}", start.elapsed());

            info!("total time: {:?}", total_time.elapsed());
            info!("PROVER DONE!");
        }
    }
    Ok(())
}

fn run(args: &Cli) -> Result<()> {
    let config = if let Some(config) = &args.config {
        Config::from_toml_file(config)?
    } else {
        Config::default()
    };

    if args.witness.is_some() {
        info!("prover mode");
    } else {
        info!("verifier mode");
    }
    info!("addr:       {:?}", args.connection_addr);
    info!("lpn:        {:?}", config.lpn());
    info!("nobatching: {:?}", config.no_batching());
    info!("instance:   {:?}", args.instance);
    info!("text fmt:   {:?}", args.text);
    info!("threads:    {:?}", config.threads());

    if args.text {
        if config.threads() == 1 {
            run_text(args, &config)
        } else {
            assert!(config.threads() > 1);
            run_text_multihtreaded(args, &config)
        }
    } else {
        if config.threads() == 1 {
            run_flatbuffers(args, &config)
        } else {
            assert!(config.threads() > 1);
            run_flatbuffers_multihtreaded(args, &config)
        }
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
