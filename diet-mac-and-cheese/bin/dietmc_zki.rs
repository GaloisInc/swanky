mod cli;

use clap::Parser;
use cli::{map_lpn_size, Cli, Prover::*};
use diet_mac_and_cheese::{
    backend_trait::BackendT, DietMacAndCheeseProver, DietMacAndCheeseVerifier,
};
use log::info;
use pretty_env_logger;
#[cfg(feature = "ff")]
use scuttlebutt::field::{F384p, F384q};
use scuttlebutt::{
    field::{
        //F128p,
        F40b,
        F61p,
        FiniteField,
    },
    AesRng, SyncChannel, TrackChannel,
};
use std::env;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Instant;
use zki_sieve::{Message, Source};

// Read a flatbuffer sieveir message from a path and returns its field as a vector of bytes.
fn get_field(path: PathBuf) -> zki_sieve::Result<Vec<u8>> {
    let mut header = None;

    if path.clone().is_file() {
        header = match Source::from_filenames(vec![path])
            .iter_messages()
            .next()
            .unwrap()?
        {
            zki_sieve::Message::Instance(m) => Some(m.header),
            zki_sieve::Message::Witness(m) => Some(m.header),
            zki_sieve::Message::Relation(m) => Some(m.header),
        };
    } else {
        if path.is_dir() {
            for m in Source::from_directory(path.as_path())?.iter_messages() {
                match m.unwrap() {
                    zki_sieve::Message::Instance(m) => {
                        header = Some(m.header);
                        break;
                    }
                    zki_sieve::Message::Witness(m) => {
                        header = Some(m.header);
                        break;
                    }
                    zki_sieve::Message::Relation(m) => {
                        header = Some(m.header);
                        break;
                    }
                }
            }
        }
    }

    match header {
        Some(header) => {
            let header = header;

            if header.field_degree.clone() != 1 {
                return zki_sieve::Result::Err(
                    format!(
                        "Illegal header field degree {:?}",
                        header.field_degree.clone()
                    )
                    .into(),
                );
            }
            let mut characteristic = header.field_characteristic;
            while characteristic.last() == Some(&0) {
                characteristic.pop();
            }

            zki_sieve::Result::Ok(characteristic)
        }
        None => zki_sieve::Result::Err("No header available".into()),
    }
}

fn run<FE: FiniteField>(args: &Cli) -> std::io::Result<()> {
    if args.command.is_some() {
        info!("prover mode");
    } else {
        info!("verifier mode");
    }
    info!("addr: {:?}", args.connection_addr);
    info!("lpn: {:?}", args.lpn);
    info!("instance: {:?}", args.instance);
    info!("nobatching: {:?}", args.nobatching);

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

    let (lpn_setup, lpn_extend) = map_lpn_size(&args.lpn);

    let instance_path = args.instance.clone();
    let relation_path = args.relation.clone();

    let start = Instant::now();
    let instance_source = Source::from_filenames(vec![instance_path]);
    let instances = instance_source.iter_messages().map(|msg| {
        msg.and_then(|msg| match msg {
            Message::Instance(x) => Ok(x),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected instance",
            ))),
        })
    });

    let witness_source = Source::from_filenames(vec![witness_path]);
    let witnesses = witness_source.iter_messages().map(|msg| {
        msg.and_then(|msg| match msg {
            Message::Witness(x) => Ok(x),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected witness",
            ))),
        })
    });

    let relation_source;
    if relation_path.is_file() {
        relation_source = Source::from_filenames(vec![relation_path.clone()]);
    } else {
        relation_source = Source::from_directory(relation_path.clone().as_path()).unwrap();
    }

    let relations = relation_source.iter_messages().map(|msg| {
        msg.and_then(|msg| match msg {
            Message::Relation(x) => Ok(x),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected relation",
            ))),
        })
    });

    info!("file prep time: {:?}", start.elapsed());

    if args.command.is_none() {
        let listener = TcpListener::bind(args.connection_addr.clone())?;
        match listener.accept() {
            Ok((stream, _addr)) => {
                info!("connection received");
                let reader = BufReader::new(stream.try_clone().unwrap());
                let writer = BufWriter::new(stream);
                let mut channel = TrackChannel::new(SyncChannel::new(reader, writer));
                let rng = AesRng::new();
                let start = Instant::now();

                let mut zkbackend = DietMacAndCheeseVerifier::<FE, _, _>::init(
                    &mut channel,
                    rng,
                    lpn_setup,
                    lpn_extend,
                    args.nobatching,
                )
                .unwrap();
                info!("init time: {:?}", start.elapsed());

                let mut eval = zki_sieve::consumers::evaluator::Evaluator::<
                    DietMacAndCheeseVerifier<FE, _, _>,
                >::default();
                let start = Instant::now();
                for ins in instances {
                    eval.ingest_instance(&ins.unwrap()).unwrap();
                }
                info!("instance time: {:?}", start.elapsed());

                let start = Instant::now();
                for rel in relations {
                    eval.ingest_relation(&rel.unwrap(), &mut zkbackend).unwrap();
                }

                zkbackend.finalize().unwrap();

                info!("time: {:?}", start.elapsed());
                info!("VERIFIER DONE!");
            }
            Err(e) => info!("couldn't get client: {:?}", e),
        }
    } else {
        // Prover mode

        let stream = TcpStream::connect(args.connection_addr.clone())?;
        let reader = BufReader::new(stream.try_clone().unwrap());
        let writer = BufWriter::new(stream);
        let mut channel = TrackChannel::new(SyncChannel::new(reader, writer));
        let rng = AesRng::new();
        let start = Instant::now();

        let mut zkbackend = DietMacAndCheeseProver::<FE, _, _>::init(
            &mut channel,
            rng,
            lpn_setup,
            lpn_extend,
            args.nobatching,
        )
        .unwrap();
        info!("init time: {:?}", start.elapsed());

        let start = Instant::now();
        let mut eval =
            zki_sieve::consumers::evaluator::Evaluator::<DietMacAndCheeseProver<FE, _, _>>::default(
            );
        for ins in instances {
            eval.ingest_instance(&ins.unwrap()).unwrap();
        }
        info!("instance time: {:?}", start.elapsed());

        for wit in witnesses {
            eval.ingest_witness(&wit.unwrap()).unwrap();
        }
        info!("witness time: {:?}", start.elapsed());

        let start = Instant::now();
        for rel in relations {
            eval.ingest_relation(&rel.unwrap(), &mut zkbackend).unwrap();
        }

        zkbackend.finalize().unwrap();

        let input_comm_sent = channel.kilobits_written();
        let input_comm_recv = channel.kilobits_read();
        info!("prover sends {} Mb", input_comm_sent / 1000.0);
        info!("prover reads {} Mb", input_comm_recv / 1000.0);
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

    let path = cli.instance.clone();
    let field = get_field(path);
    if field.is_err() {
        return std::io::Result::Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "cant read the field",
        ));
    }
    match field.unwrap().as_slice() {
        &[2] => {
            info!("field: F40b");
            run::<F40b>(&cli)
        }
        &[255, 255, 255, 255, 255, 255, 255, 31] => {
            info!("field: f61p");
            run::<F61p>(&cli)
        }
        // &[97, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] => {
        //    info!("field: Fp");
        //    run::<F128p>(whoami, connection_addr, field, instance, witness, relation)
        // }
        // &[1, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48] => {
        //     run::<scuttlebutt::field::FBn128>(whoami, connection_addr, field, instance, witness, relation)
        // }
        // &[237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127] => {
        //     run::<scuttlebutt::field::F255p>(whoami, connection_addr, field, instance, witness, relation)
        // }
        &[255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] =>
        {
            #[cfg(feature = "ff")]
            {
                info!("field: F384p");
                run::<F384p>(&cli)
            }
            #[cfg(not(feature = "ff"))]
            {
                panic!("Set feature ff for F384p")
            }
        }
        &[115, 41, 197, 204, 106, 25, 236, 236, 122, 167, 176, 72, 178, 13, 26, 88, 223, 45, 55, 244, 129, 77, 99, 199, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] =>
        {
            #[cfg(feature = "ff")]
            {
                info!("field: F394q");
                run::<F384q>(&cli)
            }
            #[cfg(not(feature = "ff"))]
            {
                panic!("Set feature ff for F384q")
            }
        }
        x => std::io::Result::Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Unknown or unsupported field {:?}", x),
        )),
    }
}
