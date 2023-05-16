use std::{fs::File, path::PathBuf, time::Instant};

use clap::{Args, Subcommand};
use eyre::{Context, ContextCompat};
use mac_n_cheese_ir::circuit_builder::build_privates;
use mac_n_cheese_party::{private::ProverPrivate, Party, WhichParty, IS_VERIFIER};
use mac_n_cheese_sieve_parser::{RelationReader, ValueStreamKind, ValueStreamReader};
use mac_n_cheese_wire_map::WireMap;

use self::{
    circuit_ir::CircuitChunk,
    supported_fields::{CompilerField, FieldIndexedArray, FieldType},
};

#[macro_use]
mod supported_fields;

mod circuit_ir;
mod plaintext_eval;
mod simple_writer;
// mod writer;

#[derive(Args)]
pub struct SieveArgs {
    // If set, inputs are in text format, not flatbuffers
    #[clap(long)]
    text: bool,
    // folders can be provided. Items will be sorted by _path_, not by file name.
    // no protection against symlink loops
    #[clap(long)]
    public_inputs: Vec<PathBuf>,
    #[clap(long, required = true)]
    relation: PathBuf,
    #[clap(long, short)]
    out: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    PlaintextEvaluate { witness: Vec<PathBuf> },
    CompileProver { witness: Vec<PathBuf> },
    CompileVerifier,
}

fn to_fe<FE: CompilerField>(x: usize) -> eyre::Result<FE> {
    Ok(match FE::PrimeField::try_from(x as u128) {
        Ok(x) => x,
        Err(_) => {
            eyre::bail!("Value larger than prime field modulus")
        }
    }
    .into())
}

// Convert x to a k-bit little-endian number
fn to_k_bits<FE: CompilerField>(x: usize, k: usize) -> eyre::Result<Vec<FE>> {
    let mut bits = Vec::with_capacity(k);

    let mut quot = x;
    while quot != 0 {
        bits.push(if quot % 2 == 0 { FE::ZERO } else { FE::ONE });
        quot /= 2;
    }

    if bits.len() > k {
        eyre::bail!("{x} cannot be expressed in {k} bits");
    } else {
        bits.append(&mut vec![FE::ZERO; k - bits.len()]);
        Ok(bits)
    }
}

// Convert x to a k-bit litle-endian number, inverting all bits
fn to_k_flipped_bits<FE: CompilerField>(x: usize, k: usize) -> eyre::Result<Vec<FE>> {
    let mut bits = Vec::with_capacity(k);

    let mut quot = x;
    while quot != 0 {
        bits.push(if quot % 2 == 0 { FE::ONE } else { FE::ZERO });
        quot /= 2;
    }

    if bits.len() > k {
        eyre::bail!("{x} cannot be expressed in {k} bits");
    } else {
        bits.append(&mut vec![FE::ONE; k - bits.len()]);
        Ok(bits)
    }
}

fn put<T>(wm: &mut WireMap<T>, wire: mac_n_cheese_wire_map::WireId, value: T) -> eyre::Result<()> {
    match wm.insert(wire, value) {
        mac_n_cheese_wire_map::InsertResult::NotAllocated(value) => {
            // Per the sieve IR spec, we need to allocate space for this one wire.
            wm.alloc(wire, wire)?;
            let _result = wm.insert(wire, value);
            debug_assert!(matches!(
                _result,
                mac_n_cheese_wire_map::InsertResult::PreviouslyUnset
            ));
        }
        mac_n_cheese_wire_map::InsertResult::PreviouslyUnset => {}
        mac_n_cheese_wire_map::InsertResult::PreviouslySet => {
            eyre::bail!("Wire {wire} was previously set")
        }
        mac_n_cheese_wire_map::InsertResult::AllocationNotMutable => {
            eyre::bail!("Wire {wire} is read-only in this scope")
        }
    }
    Ok(())
}

struct Inputs<VSR: ValueStreamReader>(FieldIndexedArray<Option<VSR>>, ValueStreamKind);
impl<VSR: ValueStreamReader> Inputs<VSR> {
    fn open(kind: ValueStreamKind, paths: &[PathBuf]) -> eyre::Result<Self> {
        let mut out: FieldIndexedArray<Option<VSR>> = Default::default();
        for path in paths {
            let rr = VSR::open(kind, path).with_context(|| format!("Opening {path:?}"))?;
            let ft = FieldType::from_modulus(rr.modulus())
                .with_context(|| format!("Unknown modulus {}", rr.modulus()))?;
            eyre::ensure!(
                out[ft].is_none(),
                "Multiple files for {kind:?} {}",
                rr.modulus()
            );
            out[ft] = Some(rr);
        }
        Ok(Self(out, kind))
    }

    pub fn read_into<FE: CompilerField>(
        &mut self,
        n: usize,
        dst: &mut Vec<FE>,
    ) -> eyre::Result<()> {
        // It's not super efficient that we keep re-entering the read for each public input that we
        // need. However it seems like public inputs are rarely used, so it's hopefully a non-issue.
        if n == 0 {
            return Ok(());
        }
        let src = self.0[FE::FIELD_TYPE]
            .as_mut()
            .with_context(|| format!("No {:?} inputs provided for {:?}", self.1, FE::FIELD_TYPE))?;
        dst.reserve(n);
        for _ in 0..n {
            let num = src
                .next()?
                .with_context(|| format!("Ran out of {:?} {:?} inputs", self.1, FE::FIELD_TYPE))?;
            dst.push(FE::parse_sieve_value(&num)?);
        }
        Ok(())
    }
}

fn sieve_compiler_main_party<
    P: Party,
    RR: RelationReader + Send + 'static,
    VSR: ValueStreamReader + Send + 'static,
>(
    args: &SieveArgs,
    witness_path: ProverPrivate<P, &[PathBuf]>,
) -> eyre::Result<()> {
    let start = Instant::now();
    let witnesses = witness_path
        .map(|x| Inputs::<VSR>::open(ValueStreamKind::Private, x))
        .lift_result()?;
    let chunks = CircuitChunk::stream::<RR, VSR>(&args.relation, &args.public_inputs);
    match P::WHICH {
        WhichParty::Prover(_) => build_privates(args.out.with_extension("priv"), |pb| {
            simple_writer::write_circuit(&args.out, chunks, witnesses, ProverPrivate::new(pb))
        }),
        WhichParty::Verifier(e) => simple_writer::write_circuit::<P, VSR>(
            &args.out,
            chunks,
            ProverPrivate::empty(e),
            ProverPrivate::empty(e),
        ),
    }
    .context("circuit writing failed")?;
    eprintln!("Circuit writing finished in {:?}", start.elapsed());
    Ok(())
}

pub fn sieve_compiler_main(args: SieveArgs) -> eyre::Result<()> {
    std::thread::Builder::new()
        .name("Main Thread".to_string())
        .spawn::<_, eyre::Result<()>>(move || {
            match &args.command {
                Command::CompileProver { witness } => {
                    let witness_path: ProverPrivate<_, &[PathBuf]> = ProverPrivate::new(witness);
                    if args.text {
                        sieve_compiler_main_party::<
                            mac_n_cheese_party::Prover,
                            mac_n_cheese_sieve_parser::text_parser::RelationReader<File>,
                            mac_n_cheese_sieve_parser::text_parser::ValueStreamReader<File>,
                        >(&args, witness_path)?;
                    } else {
                        sieve_compiler_main_party::<
                            mac_n_cheese_party::Prover,
                            mac_n_cheese_sieve_parser::fb_reader::RelationReader,
                            mac_n_cheese_sieve_parser::fb_reader::ValueStreamReader,
                        >(&args, witness_path)?;
                    }
                }
                Command::CompileVerifier => {
                    if args.text {
                        sieve_compiler_main_party::<
                            mac_n_cheese_party::Verifier,
                            mac_n_cheese_sieve_parser::text_parser::RelationReader<File>,
                            mac_n_cheese_sieve_parser::text_parser::ValueStreamReader<File>,
                        >(&args, ProverPrivate::empty(IS_VERIFIER))?
                    } else {
                        sieve_compiler_main_party::<
                            mac_n_cheese_party::Verifier,
                            mac_n_cheese_sieve_parser::fb_reader::RelationReader,
                            mac_n_cheese_sieve_parser::fb_reader::ValueStreamReader,
                        >(&args, ProverPrivate::empty(IS_VERIFIER))?
                    }
                }
                Command::PlaintextEvaluate { witness } => {
                    if args.text {
                        plaintext_eval::plaintext_evaluate::<
                            mac_n_cheese_sieve_parser::text_parser::RelationReader<File>,
                            mac_n_cheese_sieve_parser::text_parser::ValueStreamReader<File>,
                        >(&args, witness)?;
                    } else {
                        plaintext_eval::plaintext_evaluate::<
                            mac_n_cheese_sieve_parser::fb_reader::RelationReader,
                            mac_n_cheese_sieve_parser::fb_reader::ValueStreamReader,
                        >(&args, witness)?;
                    }
                }
            }
            Ok(())
        })
        .unwrap()
        .join()
        .unwrap()
}
