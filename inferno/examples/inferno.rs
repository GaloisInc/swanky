use clap::Parser;
use inferno::Proof;
use rand::SeedableRng;
use scuttlebutt::field::F64b;
use scuttlebutt::{field::FiniteField, AesRng};
use simple_arith_circuit::Circuit;
use std::io::Write;
use std::path::{Path, PathBuf};

const N: usize = 16;
const K: usize = 8;
const T: usize = 40;

fn circuitgen<F: FiniteField>(
    rng: &mut AesRng,
    mults_only: bool,
    ninputs: usize,
    ngates: usize,
) -> (Circuit<F::PrimeField>, Vec<F::PrimeField>) {
    let (circuit, witness) = if mults_only {
        log::info!(
            "Generating circuit containing {} inputs and {} multiplication gates",
            ninputs,
            ngates,
        );
        simple_arith_circuit::circuitgen::mul_zero_circuit::<F::PrimeField, AesRng>(
            ninputs, ngates, rng,
        )
    } else {
        log::info!(
            "Generating random circuit containing {} inputs and {} gates",
            ninputs,
            ngates
        );
        simple_arith_circuit::circuitgen::random_zero_circuit::<F::PrimeField, AesRng>(
            ninputs, ngates, rng,
        )
    };
    (circuit, witness)
}

fn prover<F: FiniteField>(args: Args) {
    let mut rng = AesRng::from_entropy();

    let (circuit, witness) = circuitgen::<F>(&mut rng, args.mults_only, args.ninputs, args.ngates);

    log::info!("> # multiplication gates: {}", circuit.nmuls());
    log::info!("> # non-multiplication gates: {}", circuit.nnonmuls());

    log::info!("Running prover: N = {N}, K = {K}, T = {T}");
    let time = std::time::Instant::now();
    let proof = Proof::<F, N>::prove(&circuit, &witness, K, T, &mut rng);
    let prover_time = time.elapsed().as_millis();

    log::info!("Serializing proof");
    let time = std::time::Instant::now();
    let serialized = bincode::serialize(&proof).unwrap();
    let serialization_time = time.elapsed().as_millis();

    if let Some(filename) = args.filename.as_ref() {
        log::info!("Writing proof to '{:?}'", filename);
        let mut file = std::fs::File::create(filename).unwrap();
        file.write(&serialized).unwrap();

        let serialized = bincode::serialize(&circuit).unwrap();
        let circuitfile = filename.with_extension("circuit");
        log::info!("Writing circuit to '{:?}", circuitfile);
        let mut file = std::fs::File::create(circuitfile).unwrap();
        file.write(&serialized).unwrap();
    }

    let time = std::time::Instant::now();
    if !args.prover_only {
        log::info!("Running verifier");
        let result = proof.verify(&circuit, K, T);
        if result.is_ok() {
            println!("Verifier succeeded!");
        } else {
            println!("Verifier failed?!");
        }
    }
    let verifier_time = time.elapsed().as_millis();
    println!("> Prover running time: {} ms", prover_time);
    if !args.prover_only {
        println!("> Verifier running time: {} ms", verifier_time);
    }
    println!("> Proof size: {} KB", serialized.len() / 1024);
    println!("> Serialization time: {} ms", serialization_time);
}

fn verifier<F: FiniteField>(filename: &Path) {
    log::info!("Reading proof from '{:?}'", filename);
    let file = std::fs::File::open(filename).unwrap();
    let proof: Proof<F, N> = bincode::deserialize_from(file).unwrap();

    let circuitfile = filename.with_extension("circuit");
    log::info!("Reading circuit from '{:?}", circuitfile);
    let file = std::fs::File::open(circuitfile).unwrap();
    let circuit: Circuit<F::PrimeField> = bincode::deserialize_from(file).unwrap();

    log::info!("Running verifier");
    let result = proof.verify(&circuit, K, T);
    if result.is_ok() {
        println!("Verifier succeeded!");
    } else {
        println!("Verifier failed?!");
    }
}

#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    /// Enable logging
    #[clap(long)]
    logging: bool,

    /// Only run the prover
    #[clap(long)]
    prover_only: bool,

    /// Only run the verifier
    #[clap(long)]
    verifier_only: bool,

    /// Number of inputs (a.k.a. the witness length)
    #[clap(long, default_value_t = 10)]
    ninputs: usize,

    /// Number of gates
    #[clap(long, default_value_t = 1_000_000)]
    ngates: usize,

    /// Only generate multiplication gates
    #[clap(long)]
    mults_only: bool,

    /// Save/load proof to/from disk
    #[clap(long)]
    filename: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    if args.logging {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    if args.verifier_only {
        if let Some(filename) = args.filename.as_ref() {
            verifier::<F64b>(filename);
        } else {
            eprintln!("Error: --filename must be given if --verifier-only is used");
            std::process::exit(1);
        }
    } else {
        prover::<F64b>(args);
    }
}
