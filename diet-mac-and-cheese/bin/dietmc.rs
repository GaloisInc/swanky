mod cli;

use crate::cli::Config;
use clap::Parser;
use cli::Cli;
use diet_mac_and_cheese::backend_multifield::EvaluatorCirc;
use diet_mac_and_cheese::circuit_ir::{CircInputs, TypeStore};
use diet_mac_and_cheese::sieveir_reader_fbs::{read_types, InputFlatbuffers};
use diet_mac_and_cheese::sieveir_reader_text::InputText;
use diet_mac_and_cheese::svole_thread::SvoleAtomic;
use diet_mac_and_cheese::svole_trait::Svole;
use eyre::{bail, Result, WrapErr};
use log::info;
use mac_n_cheese_sieve_parser::text_parser::RelationReader;
use mac_n_cheese_sieve_parser::RelationReader as RR;
use scuttlebutt::field::{F40b, F2};
use scuttlebutt::AbstractChannel;
use scuttlebutt::{AesRng, Channel, SyncChannel};
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::marker::PhantomData;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Instant;
use swanky_party::{Party, Prover, Verifier, WhichParty};

#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
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
                path.wrap_err_with(|| "error reading dir path".to_string())?
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

/// Structure to generate a stream of channels given a set of addresses.
struct ChannelIterator<P: Party, C: AbstractChannel> {
    addresses: Vec<String>,
    idx: usize,
    phantom: PhantomData<(P, C)>,
}

impl<P: Party, C: AbstractChannel> ChannelIterator<P, C> {
    /// Create a new [`ChannelIterator`] given a list of addresses.
    fn new(addresses: &[String]) -> Self {
        Self {
            addresses: addresses.to_vec(),
            idx: 0,
            phantom: PhantomData,
        }
    }

    /// Next address when there is one.
    fn next_address(&mut self) -> Option<String> {
        if self.idx >= self.addresses.len() {
            None
        } else {
            let addr = self.addresses[self.idx].clone();
            self.idx += 1;
            Some(addr)
        }
    }
}

impl<P: Party> Iterator
    for ChannelIterator<P, SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>
{
    type Item = SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(addr) = self.next_address() {
            match P::WHICH {
                WhichParty::Verifier(_ev) => {
                    if let Ok(listener) = TcpListener::bind(addr.clone()) {
                        if let Ok((stream, _addr)) = listener.accept() {
                            info!("accept connection on {:?}", addr);
                            let reader = BufReader::new(stream.try_clone().unwrap());
                            let writer = BufWriter::new(stream);
                            Some(SyncChannel::new(reader, writer))
                        } else {
                            info!("Error accepting addr {:?}", addr);
                            None
                        }
                    } else {
                        log::error!("Error binding addr {}", addr);
                        None
                    }
                }
                WhichParty::Prover(_) => loop {
                    let c = TcpStream::connect(addr.clone());
                    if let Ok(stream) = c {
                        info!("connection accepted by {:?}", addr);
                        let reader = BufReader::new(stream.try_clone().unwrap());
                        let writer = BufWriter::new(stream);
                        return Some(SyncChannel::new(reader, writer));
                    }
                },
            }
        } else {
            None
        }
    }
}

fn build_inputs_types_text(args: &Cli) -> Result<(CircInputs, TypeStore)> {
    info!("relation: {:?}", args.relation);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

    let mut inputs = CircInputs::default();

    let instance_paths = path_to_files(instance_path)?;
    for (i, instance_path) in instance_paths.iter().enumerate() {
        let instances_stream = InputText::new_public_inputs(instance_path)?;
        inputs.set_instances(i, Box::new(instances_stream));
        info!("Loaded idx:{:?} file:{:?}", i, instance_path,);
    }

    if let Some(witness) = &args.witness {
        // Prover mode
        info!("witness: {:?}", witness);
        let witness_paths = path_to_files(witness.to_path_buf())?;
        for (i, witness_path) in witness_paths.iter().enumerate() {
            let witnesses_stream = InputText::new_private_inputs(witness_path)?;
            inputs.set_witnesses(i, Box::new(witnesses_stream));
            info!("Loaded idx:{:?} file:{:?}", i, witness_path,);
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
        let instances = InputFlatbuffers::new_public_inputs(instance_path)?;
        inputs.set_instances(i, Box::new(instances));
        info!("Loaded idx:{:?} file:{:?}", i, instance_path,);
    }

    if let Some(witness) = &args.witness {
        // Prover mode
        info!("witness: {:?}", witness);
        let witness_paths = path_to_files(witness.to_path_buf())?;
        for (i, witness_path) in witness_paths.iter().enumerate() {
            let witnesses = InputFlatbuffers::new_private_inputs(witness_path)?;
            inputs.set_witnesses(i, Box::new(witnesses));
            info!("Loaded idx:{:?} file:{:?}", i, witness_path,);
        }
    }

    info!("time reading ins/wit/rel: {:?}", start.elapsed());
    Ok((inputs, fields))
}

// Run singlethreaded
fn run_singlethreaded(args: &Cli, config: &Config, is_text: bool) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = if is_text {
        build_inputs_types_text(args)?
    } else {
        build_inputs_flatbuffers(args)?
    };
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            // Verifier mode
            let mut conns = start_connection_verifier(&[args.connection_addr.clone()])?;
            let stream = conns.pop().unwrap();

            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator =
                EvaluatorCirc::<Verifier, _, Svole<_, F2, F40b>, Svole<_, F40b, F40b>>::new(
                    &mut channel,
                    rng,
                    inputs,
                    type_store,
                    config.lpn(),
                    config.no_batching(),
                )?;
            evaluator.load_backends(&mut channel, config.lpn())?;
            info!("init time: {:?}", start.elapsed());

            let start = Instant::now();
            if is_text {
                let relation_file = File::open(relation_path)?;
                let relation_reader = BufReader::new(relation_file);
                evaluator.evaluate_relation_text(relation_reader)?;
            } else {
                evaluator.evaluate_relation(&relation_path)?;
            }
            info!("time circ exec: {:?}", start.elapsed());
            info!("VERIFIER DONE!");
        }
        Some(_) => {
            // Prover mode
            let mut conns = start_connection_prover(&[args.connection_addr.clone()])?;
            let stream = conns.pop().unwrap();

            let reader = BufReader::new(stream.try_clone()?);
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = Instant::now();
            let rng = AesRng::new();

            let mut evaluator =
                EvaluatorCirc::<Prover, _, Svole<_, F2, F40b>, Svole<_, F40b, F40b>>::new(
                    &mut channel,
                    rng,
                    inputs,
                    type_store,
                    config.lpn(),
                    config.no_batching(),
                )?;
            evaluator.load_backends(&mut channel, config.lpn())?;
            info!("init time: {:?}", start.elapsed());
            let start = Instant::now();
            if is_text {
                let relation_file = File::open(relation_path)?;
                let relation_reader = BufReader::new(relation_file);
                evaluator.evaluate_relation_text(relation_reader)?;
            } else {
                evaluator.evaluate_relation(&relation_path)?;
            }
            info!("time circ exec: {:?}", start.elapsed());
            info!("PROVER DONE!");
        }
    }
    Ok(())
}

// Run multithreaded
fn run_multithreaded(args: &Cli, config: &Config, is_text: bool) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = if is_text {
        build_inputs_types_text(args)?
    } else {
        build_inputs_flatbuffers(args)?
    };
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let addresses: Vec<String> = parse_addresses(args, config);

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            // Verifier mode
            let mut channels = ChannelIterator::<
                Verifier,
                SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>,
            >::new(&addresses);

            // This is the channel for the main thread
            let mut channel = if let Some(c) = channels.next() {
                c
            } else {
                bail!("cannot open first channel");
            };

            let init_time = Instant::now();
            let total_time = Instant::now();

            let rng = AesRng::new();

            let mut handles = vec![];
            let (mut evaluator, handles_f2) = EvaluatorCirc::<
                Verifier,
                _,
                SvoleAtomic<_, F2, F40b>,
                SvoleAtomic<_, F40b, F40b>,
            >::new_multithreaded(
                &mut channels,
                config.threads_per_field(),
                rng,
                inputs,
                type_store,
                config.no_batching(),
                config.lpn(),
            )?;
            handles.extend(handles_f2);

            let handles_fields = evaluator.load_backends_multithreaded(
                &mut channel,
                &mut channels,
                config.lpn(),
                config.threads_per_field(),
            )?;
            handles.extend(handles_fields);
            info!("init time: {:?}", init_time.elapsed());

            let start = Instant::now();
            if is_text {
                let relation_file = File::open(relation_path)?;
                let relation_reader = BufReader::new(relation_file);
                evaluator.evaluate_relation_text(relation_reader)?;
            } else {
                evaluator.evaluate_relation(&relation_path)?;
            }
            evaluator.terminate()?;
            for handle in handles {
                handle.join().expect("thread failed to join")?;
            }
            info!("circ exec time: {:?}", start.elapsed());

            info!("total time: {:?}", total_time.elapsed());
            info!("VERIFIER DONE!");
        }
        Some(_) => {
            // Prover mode
            let mut channels = ChannelIterator::<
                Prover,
                SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>,
            >::new(&addresses);

            // This is the channel for the main thread
            let mut channel = if let Some(c) = channels.next() {
                c
            } else {
                bail!("cannot open first channel");
            };

            let init_time = Instant::now();
            let total_time = Instant::now();

            let rng = AesRng::new();

            let mut handles = vec![];
            let (mut evaluator, handles_f2) = EvaluatorCirc::<
                Prover,
                _,
                SvoleAtomic<_, F2, F40b>,
                SvoleAtomic<_, F40b, F40b>,
            >::new_multithreaded(
                &mut channels,
                config.threads_per_field(),
                rng,
                inputs,
                type_store,
                config.no_batching(),
                config.lpn(),
            )?;
            handles.extend(handles_f2);

            let handles_fields = evaluator.load_backends_multithreaded(
                &mut channel,
                &mut channels,
                config.lpn(),
                config.threads_per_field(),
            )?;
            handles.extend(handles_fields);
            info!("init time: {:?}", init_time.elapsed());

            let start = Instant::now();
            if is_text {
                let relation_file = File::open(relation_path)?;
                let relation_reader = BufReader::new(relation_file);
                evaluator.evaluate_relation_text(relation_reader)?;
            } else {
                evaluator.evaluate_relation(&relation_path)?;
            }
            evaluator.terminate()?;
            for handle in handles {
                handle.join().expect("thread failed to join")?;
            }
            info!("circ exec time: {:?}", start.elapsed());

            info!("total time: {:?}", total_time.elapsed());
            info!("PROVER DONE!");
        }
    }
    Ok(())
}

fn run_plaintext(args: &Cli) -> Result<()> {
    let start = Instant::now();
    let (inputs, type_store) = if args.text {
        build_inputs_types_text(args)?
    } else {
        build_inputs_flatbuffers(args)?
    };
    info!("time reading ins/wit/rel: {:?}", start.elapsed());

    let relation_path = args.relation.clone();
    match args.witness {
        None => {
            eyre::bail!("Plaintext evaluation requires a witness to be provided.");
        }
        Some(_) => {
            // Prover mode
            let start = Instant::now();

            let mut evaluator = EvaluatorCirc::<
                Prover,
                SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>, // unnecessary type
                Svole<_, F2, F40b>,
                Svole<_, F40b, F40b>,
            >::new_plaintext(inputs, type_store)?;
            evaluator.load_backends_plaintext()?;
            info!("init time: {:?}", start.elapsed());
            let start = Instant::now();

            if args.text {
                let relation_file = File::open(relation_path)?;
                let relation_reader = BufReader::new(relation_file);
                evaluator.evaluate_relation_text(relation_reader)?;
            } else {
                evaluator.evaluate_relation(&relation_path)?;
            }
            evaluator.terminate()?;
            info!("time circ exec: {:?}", start.elapsed());
        }
    }
    Ok(())
}

fn parse_addresses(args: &Cli, config: &Config) -> Vec<String> {
    let mut addresses: Vec<String> = args
        .connection_addr
        .clone()
        .split(',')
        .map(|x| x.into())
        .collect();
    // if there are not enough addresses then add some other ones
    if addresses.len() == 1 {
        let split_addr: Vec<String> = addresses[0].clone().split(':').map(|x| x.into()).collect();
        let addr = split_addr[0].clone();
        let port: usize = split_addr[1]
            .clone()
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("cant parse port"));
        for i in 1..config.threads() {
            let mut new_addr = addr.clone();
            new_addr.push(':');
            let new_port = format!("{:?}", port + i);
            new_addr.push_str(&new_port);
            addresses.push(new_addr);
        }
    }
    addresses
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

    if args.plaintext {
        // when running in plaintext mode, the `config` is ignored
        return run_plaintext(args);
    }
    let is_text = args.text;
    if config.threads() == 1 {
        run_singlethreaded(args, &config, is_text)
    } else {
        assert!(config.threads() > 1);
        run_multithreaded(args, &config, is_text)
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
