#![deny(unused_must_use)]

use std::fs::File;
use std::io::{Read, Write};
use std::marker::PhantomData;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use eyre::{Context, ContextCompat};
use mac_n_cheese_ir::compilation_format::fb::{self, DataChunkAddress};
use mac_n_cheese_ir::compilation_format::{
    read_private_manifest, AtomicGraphDegreeCount, Manifest, Type,
};
use mac_n_cheese_party as party;
use mac_n_cheese_party::Party;
use party::either::PartyEitherCopy;
use party::private::{ProverPrivate, ProverPrivateCopy};
use party::{WhichParty, IS_PROVER, IS_VERIFIER};
use rand::SeedableRng;
use scuttlebutt::AesRng;
use types::visit_type;

use crate::runner::RunQueue;

use crate::task_queue::{TaskQueue, QUEUE_NAME_RUN_QUEUE};
use crate::thread_spawner::ThreadSpawner;
use crate::types::TypeVisitor;

pub const MAC_N_CHEESE_RUNNER_VERSION: u64 = 1;

mod alloc;
mod base_vole;
mod bounded_queue;
mod channel_adapter;
mod event_log;
mod flatbuffers_ext;
mod keys;
mod reactor;
mod runner;
mod task_definitions;
mod task_framework;
mod task_queue;
mod thread_spawner;
mod tls;
mod type_map;
mod types;

/// A zero-knowledge proof runner.
#[derive(Parser)]
struct Opt {
    /// This should be a single file
    #[clap(short, long)]
    root_cas: PathBuf,
    /// A single PEM file containing both the private key and the signed certificate
    #[clap(short = 'k', long)]
    tls_cert: PathBuf,
    #[clap(short, long)]
    circuit: PathBuf,
    #[clap(short, long)]
    address: SocketAddr,
    #[clap(long)]
    event_log: Option<PathBuf>,
    /// If this isn't supplied, then use the number of CPUs on the machine.
    #[clap(long)]
    num_threads: Option<usize>,
    /// If specified, write the proof's run time (in nanoseconds) to this path.
    #[clap(long)]
    write_run_time_to: Option<PathBuf>,
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser)]
enum Command {
    Prove {
        private_data: PathBuf,
    },
    Verify {
        #[clap(long, default_value = "16")]
        num_connections: usize,
    },
}

fn setup_panic_handler() {
    // a panic on any thread will kill the process.
    let orig = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        orig(info);
        std::process::exit(1);
    }));
}

fn read_atomic_graph_degree_counts(
    manifest: &Manifest,
    addr: &DataChunkAddress,
) -> eyre::Result<Vec<AtomicGraphDegreeCount>> {
    let num_bytes = addr.length() as usize;
    eyre::ensure!(
        num_bytes % std::mem::size_of::<AtomicGraphDegreeCount>() == 0,
        "invalid atomic degree count data chunk"
    );
    let len = num_bytes / std::mem::size_of::<AtomicGraphDegreeCount>();
    // TODO: when Box::new_zeroed_slice gets stabilized, use that instead.
    let mut out = Vec::with_capacity(len);
    unsafe {
        // SAFETY: AtomicGraphDegreeCount "has the same in-memory representation as the
        // underlying integer type." And the underlying integer type is zeroable.
        // out was allocated with len capacity.
        std::ptr::write_bytes(out.as_mut_ptr(), 0, len);
        out.set_len(len);
    }
    manifest.read_data_chunk(addr, unsafe {
        // SAFETY: AtomicGraphDegreeCount "has the same in-memory representation as the
        // underlying integer type." And the underlying integer type is POD.
        std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, num_bytes)
    })?;
    Ok(out)
}

fn party_main<P: Party>(
    opt: &Opt,
    private_data: ProverPrivateCopy<P, &Path>,
    num_connections: PartyEitherCopy<P, (), usize>,
) -> eyre::Result<()> {
    let rng = AesRng::from_rng(rand::rngs::OsRng).unwrap();
    let circuit_file =
        File::open(&opt.circuit).with_context(|| format!("Opening circuit {:?}", opt.circuit))?;
    let span = event_log::ReadingCircuit.start();
    let circuit_manifest = Manifest::read(circuit_file)
        .with_context(|| format!("Reading circuit {:?}", opt.circuit))?;
    let manifest = circuit_manifest.manifest();
    span.finish();
    let mut private_file = ProverPrivate::from(private_data)
        .map(|path| File::open(path).with_context(|| format!("Opening private data {path:?}")))
        .lift_result()?;
    let private_manifest = private_file
        .as_mut()
        .map(|private_file| {
            let span = event_log::ReadingPrivates.start();
            let manifest = read_private_manifest(private_file);
            span.finish();
            manifest
        })
        .lift_result()?;
    let dependent_counts =
        read_atomic_graph_degree_counts(&circuit_manifest, manifest.dependent_counts())
            .context("Reading dependent counts")?;
    eyre::ensure!(dependent_counts.len() == manifest.tasks().len(), "");
    let dependency_counts =
        read_atomic_graph_degree_counts(&circuit_manifest, manifest.dependency_counts())
            .context("Reading dependency counts")?;
    alloc::init_alloc_pool(&mut extract_allocation_sizes::<P>(
        manifest.allocation_sizes(),
    )?);
    let (keys, mut root_conn, extra_conns) =
        tls::initiate_tls::<P>(opt.address, &opt.root_cas, &opt.tls_cert, num_connections)
            .context("initiating root tls connection")?;
    let start_time = Instant::now();
    event_log::ProofStart.submit();
    eprintln!("Starting proof!");
    match P::WHICH {
        WhichParty::Prover(_) => {
            root_conn.write_all(&circuit_manifest.hash().to_le_bytes())?;
            root_conn.flush()?;
        }
        WhichParty::Verifier(_) => {
            let mut buf = [0; 8];
            root_conn.read_exact(&mut buf)?;
            if u64::from_le_bytes(buf) != circuit_manifest.hash() {
                eprintln!("WARNING: CIRCUIT HASH MISMATCH!");
            }
        }
    }
    let circuit_manifest = Arc::new(circuit_manifest);
    // First, we spin up the reactor.
    let mut ts = ThreadSpawner::new();
    let run_queue: RunQueue<P> = Arc::new(TaskQueue::new(QUEUE_NAME_RUN_QUEUE));
    let reactor = reactor::new_reactor(
        &mut ts,
        circuit_manifest.clone(),
        private_file,
        extra_conns,
        run_queue.clone(),
        keys,
    )?;
    // Finally we can kick things off with the task graph.
    runner::run_proof_background(
        opt.num_threads.unwrap_or_else(num_cpus::get),
        rng,
        &mut ts,
        root_conn,
        run_queue,
        circuit_manifest,
        reactor,
        private_manifest,
        dependent_counts,
        dependency_counts,
    )?;
    ts.wait_on_threads()?;
    let proof_time = start_time.elapsed();
    event_log::ProofFinish.submit();
    eprintln!("Proof finished in {proof_time:?}");
    if let Some(path) = &opt.write_run_time_to {
        std::fs::write(path, proof_time.as_nanos().to_string().as_bytes())?;
    }
    Ok(())
}

fn extract_allocation_sizes<P: Party>(
    allocation_sizes: flatbuffers::Vector<flatbuffers::ForwardsUOffset<fb::AllocationSize>>,
) -> eyre::Result<Vec<usize>> {
    let mut out = Vec::with_capacity(allocation_sizes.len());
    for sz in allocation_sizes.iter() {
        out.push(
            usize::try_from(sz.count())?
                .checked_mul(if let Some(ty) = sz.type_() {
                    let ty = Type::try_from(ty.encoding())?;
                    struct V<P: Party>(PhantomData<P>);
                    impl<P: Party> TypeVisitor for V<P> {
                        type Output = usize;
                        fn visit<T: 'static + Send + Sync + Copy>(self) -> Self::Output {
                            std::mem::size_of::<T>()
                        }
                    }
                    visit_type::<P, V<P>>(ty, V::<P>(PhantomData))
                } else {
                    1 // the unit is bytes
                })
                .context("too much memory is requested")?,
        );
    }
    Ok(out)
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // Do this AFTER setting up eyre, so that we exit after running their hook.
    setup_panic_handler();
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::builder().trim_backtraces(None).build();
    let opt = Opt::parse();
    if matches!(
        vectoreyes::VECTOR_BACKEND,
        vectoreyes::VectorBackend::Scalar
    ) {
        eprintln!(
            "WARNING: this version of mac n'cheese will be using the scalar vectoreyes backend!"
        );
    }
    if let Some(log_path) = opt.event_log.as_ref() {
        event_log::open_event_log(log_path)
            .with_context(|| format!("Opening event log at {log_path:?}"))?;
    }
    let party_main_result = match &opt.cmd {
        Command::Prove { private_data } => party_main::<party::Prover>(
            &opt,
            ProverPrivateCopy::new(private_data),
            PartyEitherCopy::prover_new(IS_PROVER, ()),
        ),
        Command::Verify { num_connections } => {
            eyre::ensure!(
                *num_connections >= 2,
                "there must be at least two connections"
            );
            party_main::<party::Verifier>(
                &opt,
                ProverPrivateCopy::empty(IS_VERIFIER),
                PartyEitherCopy::verifier_new(IS_VERIFIER, *num_connections),
            )
        }
    };
    let close_error_log_result = if opt.event_log.is_some() {
        event_log::close_event_log().context("Closing event log")
    } else {
        Ok(())
    };
    // We want to show _both_ party_main_result and close_error_log_result
    match (party_main_result, close_error_log_result) {
        (Ok(()), x) => x,
        (x, Ok(())) => x,
        (Err(p_err), Err(log_err)) => {
            eprintln!("Closing the event log failed:\n{log_err}");
            Err(p_err)
        }
    }
}
