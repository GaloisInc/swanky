use anyhow::{Error, Result};
use clap::{arg, Arg, ArgAction, ArgMatches, Command};
use inferno::Proof;
use scuttlebutt::field::{F64b, F2};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::AesRng;
use simple_arith_circuit::{builder, Circuit};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const N: usize = 16; // Number of MPC parties
const K: usize = 8; // Compression factor
const T: usize = 40; // Number of repetitions

fn string_to_f2(s: &str) -> Result<Vec<F2>, Error> {
    let mut v = Vec::with_capacity(s.len());
    for c in s.chars() {
        let f = match c {
            '0' => F2::ZERO,
            '1' => F2::ONE,
            _ => F2::ONE,
        };
        v.push(f);
    }
    Ok(v)
}

fn prover(circuit_path: &Path, witness: &str, eqcheck: &str, output: &Path) -> Result<()> {
    let mut rng = AesRng::new();
    let witness = string_to_f2(witness)?;
    let eqcheck = string_to_f2(eqcheck)?;
    log::info!("Reading circuit from {:?}", circuit_path);
    let circuit = Circuit::<F2>::read_bristol_fashion(circuit_path, None)?;
    let circuit = builder::add_binary_equality_check(circuit, &eqcheck);
    log::info!("Building proof");
    let proof = Proof::<F64b, N>::prove(&circuit, &witness, K, T, &mut rng);
    log::info!("Serializing proof");
    let serialized = bincode::serialize(&proof)?;
    log::info!("Writing proof to {:?}", output);
    let mut file = File::create(output)?;
    file.write(&serialized)?;
    Ok(())
}

fn verifier(circuit_path: &Path, proof_path: &Path, eqcheck: &str) -> Result<(), Error> {
    let eqcheck = string_to_f2(eqcheck)?;
    log::info!("Reading circuit from {:?}", circuit_path);
    let circuit = Circuit::read_bristol_fashion(circuit_path, None)?;
    let circuit = builder::add_binary_equality_check(circuit, &eqcheck);
    log::info!("Reading proof from {:?}", proof_path);
    let file = File::open(proof_path)?;
    let proof: Proof<F64b, N> = bincode::deserialize_from(file)?;
    log::info!("Verifying proof");
    proof.verify(&circuit, K, T)?;
    print!("Verification succeeded!");
    Ok(())
}

fn evaluator(circuit_path: &Path, witness: &str) -> Result<(), Error> {
    let witness = string_to_f2(witness)?;
    log::info!("Reading circuit from {:?}", circuit_path);
    let circuit = Circuit::read_bristol_fashion(circuit_path, None)?;
    let mut wires = Vec::with_capacity(circuit.nwires());
    let outputs = circuit.eval(&witness, &mut wires);
    print!("Output = ");
    for output in outputs.iter() {
        let char = if *output == F2::ZERO {
            "0"
        } else if *output == F2::ONE {
            "1"
        } else {
            "-"
        };
        print!("{char}");
    }
    println!();
    Ok(())
}

fn main() {
    let matches = Command::new("inferno")
        .subcommand_required(true)
        .author("swanky authors <swanky@galois.com>")
        // Prover subcommand
        .subcommand(
            Command::new("prover")
                .about("Run the prover")
                .arg(arg!(<CIRCUIT> "The Bristol Fashion circuit to run on"))
                .arg(arg!(<WITNESS> "An encoding of the witness"))
                .arg(arg!(<EQCHECK> "An encoding of the equality check value"))
                .arg(arg!(<OUTPUT> "Where to write the proof"))
                .arg(
                    Arg::new("logging")
                        .long("logging")
                        .help("Enable logging")
                        .action(ArgAction::SetTrue),
                ),
        )
        // Verifier subcommand
        .subcommand(
            Command::new("verifier")
                .about("Run the verifier")
                .arg(arg!(<CIRCUIT> "The Bristol Fashion circuit to run on"))
                .arg(arg!(<PROOF> "The proof file to run on"))
                .arg(arg!(<EQCHECK> "An encoding of the equality check value"))
                .arg(
                    Arg::new("logging")
                        .long("logging")
                        .help("Enable logging")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("evaluator")
                .about("Evaluate the circuit")
                .arg(arg!(<CIRCUIT> "The Bristol Fashion circuit to run on"))
                .arg(arg!(<WITNESS> "An encoding of the witness"))
                .arg(
                    Arg::new("logging")
                        .long("logging")
                        .help("Enable logging")
                        .action(ArgAction::SetTrue),
                ),
        )
        .get_matches();

    fn set_logging(matches: &ArgMatches) {
        if let Some(value) = matches.get_one::<bool>("logging") {
            if *value {
                env_logger::Builder::from_default_env()
                    .filter_level(log::LevelFilter::Info)
                    .init();
            }
        }
    }

    let result = match matches.subcommand() {
        Some(("prover", matches)) => {
            let circuit = matches.get_one::<String>("CIRCUIT").expect("required");
            let circuit = PathBuf::from(circuit);
            let output = matches.get_one::<String>("OUTPUT").expect("required");
            let output = PathBuf::from(output);
            set_logging(matches);
            prover(
                &circuit,
                matches.get_one::<String>("WITNESS").expect("required"),
                matches.get_one::<String>("EQCHECK").expect("required"),
                &output,
            )
        }
        Some(("verifier", matches)) => {
            let circuit = matches.get_one::<String>("CIRCUIT").expect("required");
            let circuit = PathBuf::from(circuit);
            let proof = matches.get_one::<String>("PROOF").expect("required");
            let proof = PathBuf::from(proof);
            set_logging(matches);
            verifier(
                &circuit,
                &proof,
                matches.get_one::<String>("EQCHECK").expect("required"),
            )
        }
        Some(("evaluator", matches)) => {
            let circuit = matches.get_one::<String>("CIRCUIT").expect("required");
            let circuit = PathBuf::from(circuit);
            set_logging(matches);
            evaluator(
                &circuit,
                matches.get_one::<String>("WITNESS").expect("required"),
            )
        }
        _ => unreachable!(),
    };
    result.unwrap_or_else(|err| eprintln!("Error: {err}"))
}
