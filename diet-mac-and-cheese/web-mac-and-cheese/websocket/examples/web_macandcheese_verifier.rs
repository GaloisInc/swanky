use clap::{Arg, Command};
use core::fmt::Debug;
use diet_mac_and_cheese::backend_multifield::EvaluatorCirc;
use diet_mac_and_cheese::backend_trait::Party;
use diet_mac_and_cheese::circuit_ir::{CircInputs, TypeStore};
use diet_mac_and_cheese::text_reader::number_to_bytes;
use eyre::Result;
use log::info;
use mac_n_cheese_sieve_parser::text_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_sieve_parser::RelationReader as RR;
use mac_n_cheese_sieve_parser::ValueStreamKind;
use mac_n_cheese_sieve_parser::ValueStreamReader as VSR;
use pretty_env_logger;
use rustls::{Certificate, ServerConfig, ServerConnection};
use rustls_pemfile::{certs, pkcs8_private_keys};
use scuttlebutt::{AesRng, TrackChannel};
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tungstenite::accept;
use tungstenite::Message;
use web_mac_n_cheese_websocket::channel_websocket::WsChannel;

fn do_it<Stream: Read + Write + Debug + 'static>(
    instance: PathBuf,
    relation: PathBuf,
    connection: Stream,
) -> Result<()> {
    let start = Instant::now();
    let mut inputs = CircInputs::default();

    let mut instances = VecDeque::new();
    let mut stream_inp = ValueStreamReader::open(ValueStreamKind::Public, instance.as_path())?;

    while let Some(v) = stream_inp.next()? {
        instances.push_back(v);
    }
    let field = stream_inp.modulus();
    let type_id = 0;
    inputs.ingest_instances(type_id, instances);
    info!(
        "Loaded type_id:{:?} field:{:?} file:{:?} num public instances:{:?}",
        type_id,
        number_to_bytes(&field),
        instance,
        inputs.num_instances(type_id)
    );

    let rel = RelationReader::open(relation.as_path())?;

    let mut websocket = accept(connection).unwrap();

    let msg = websocket.read().unwrap();
    match msg {
        Message::Text(m) => {
            if m == "init".to_string() {
                println!("INIT");
            }
        }
        _ => {
            unimplemented!()
        }
    }

    let mut channel = TrackChannel::new(WsChannel::new(websocket));

    // MAC AND CHEESE STARTS
    let rng = AesRng::new();

    let no_batching = false;
    let mut evaluator = EvaluatorCirc::new(
        Party::Verifier,
        &mut channel,
        rng,
        inputs,
        TypeStore::try_from(rel.header().types.clone())?,
        false,
        no_batching,
    )?;
    let lpn_is_small = true;
    evaluator.load_backends(&mut channel, lpn_is_small)?;
    info!("init time: {:?}", start.elapsed());

    let start = Instant::now();
    let relation_file = File::open(relation.as_path())?;
    let relation_reader = BufReader::new(relation_file);
    evaluator.evaluate_relation_text(relation_reader)?;
    info!("time circ exec: {:?}", start.elapsed());
    info!("VERIFIER DONE!");

    Ok(())
}

fn main() {
    match env::var("RUST_LOG") {
        Ok(val) => println!("loglvl: {}", val),
        Err(_) => env::set_var("RUST_LOG", "info"),
    };
    pretty_env_logger::init_timed();

    let matches = Command::new("Web Mac'n'Cheese")
        .version("0.1")
        .author("")
        .about("")
        .arg(
            Arg::new("instance")
                .long("instance")
                .value_name("INSTANCE")
                .help("instance path")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("relation")
                .long("relation")
                .value_name("RELATION")
                .help("relation path")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("addr")
                .long("addr")
                .value_name("ADDR")
                .help("address")
                .action(clap::ArgAction::Set)
                .required(false),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .value_name("KEY")
                .help("pem key file")
                .action(clap::ArgAction::Set)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("cert")
                .long("cert")
                .value_name("CERT")
                .help("pem cert file")
                .action(clap::ArgAction::Set)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .get_matches();

    let binding = String::from("127.0.0.1:8080");
    let connection_addr = matches.get_one::<String>("addr").unwrap_or(&binding);

    println!("Verifier/Server started");
    println!("addr: {:?}", connection_addr);

    println!("Waiting for client to connect...");

    if matches.contains_id("key") {
        println!("SSL mode");

        let pem_file = std::fs::File::open(matches.get_one::<PathBuf>("cert").unwrap()).unwrap();
        let key_file = std::fs::File::open(matches.get_one::<PathBuf>("key").unwrap()).unwrap();
        let cert_reader = &mut BufReader::new(pem_file);
        let key_reader = &mut BufReader::new(key_file);
        let cert_chain = certs(cert_reader)
            .expect("Failed to load certificate chain")
            .into_iter()
            .map(Certificate)
            .collect();
        let mut keys = pkcs8_private_keys(key_reader).expect("Failed to load private key");
        let key_der = keys.remove(0);
        let key = rustls::PrivateKey(key_der);

        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("bad certificate/key");

        let arc_config = Arc::new(config);
        let server = TcpListener::bind(connection_addr).unwrap();

        for stream in server.incoming() {
            println!("client connected");
            // Spawn a new thread for each connection.
            let instance = matches.get_one::<PathBuf>("instance").unwrap().clone();
            let relation = matches.get_one::<PathBuf>("relation").unwrap().clone();
            let arc_config_clone = arc_config.clone();
            thread::spawn(move || {
                // Create a TLS connection from the configuration.
                let conn = ServerConnection::new(arc_config_clone).unwrap();
                // Wrap the TCP stream and the TLS session in a rustls::StreamOwned.
                let tls_stream = rustls::StreamOwned::new(conn, stream.unwrap());
                do_it(instance, relation, tls_stream).unwrap();
            });
        }
    }

    let server = TcpListener::bind(connection_addr).unwrap();
    for stream in server.incoming() {
        println!("client connected");
        // Spawn a new thread for each connection.
        let instance = matches.get_one::<PathBuf>("instance").unwrap().clone();
        let relation = matches.get_one::<PathBuf>("relation").unwrap().clone();
        thread::spawn(move || {
            do_it(instance, relation, stream.unwrap()).unwrap();
        });
    }
}
