use clap::error::ErrorKind;
use clap::{CommandFactory, Error, Parser, Subcommand};
use fancy_plaintext::{Dummy, DummyVal};
use ndarray::Array3;
use std::path::PathBuf;
use std::time::Instant;
use swanky_channel::Channel;
use swanky_error::{ErrorKind as SwankyErrorKind, swanky_error};
use swanky_garbled_nn::NeuralNet;

/// Garbled Neural Net Experiment Launcher
///
/// Runs experiments for (fancy) garbling neural nets.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The neural network directory to use.
    ///
    /// The directory must contain the following files: `model.json`,
    /// `weights.json`, either `tests.json` or `tests.csv`, and either
    /// `labels.json` or `labels.csv`.
    dir: PathBuf,
    /// Comma separated bitwidths to use for each layer (the last number is
    /// replicated).
    #[arg(short = 'w', long, default_value = "15", value_delimiter=',', value_terminator=" ", num_args = 1..)]
    bitwidth: Vec<usize>,
    /// Use secret weights.
    #[arg(short = 's', long, default_value_t = false)]
    secret: bool,
    /// Number of tests to run.
    #[arg(short = 'n', long)]
    ntests: Option<usize>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate the neural net to find the maximum bitwidth needed for each layer
    Bitwidth,
    /// Evaluate the given neural net directly over i64 values
    Direct,
    /// Test the accuracy of the fancy encoding of the neural network
    Dummy,
    /// Benchmark garbling and evaluating the neural network
    Bench {
        /// Number of iterations to run
        #[arg(short, long, default_value_t = 1)]
        niters: usize,
    },
}

pub fn main() -> swanky_error::Result<()> {
    let cli = Cli::parse();
    let mut cmd = Cli::command();

    let dir = cli.dir;
    let ntests = cli.ntests;
    let mut bitwidth = cli.bitwidth;

    let nn = NeuralNet::from_dir(&dir)?;
    println!("{nn:?}");

    print!("reading tests... ");
    let tests = swanky_garbled_nn::io::read_tests(&dir, ntests)?;
    println!("finished");

    print!("reading labels... ");
    let labels = swanky_garbled_nn::io::read_labels(&dir)?;
    println!("finished");

    // Pad the bitwidth with the last value.
    bitwidth.resize(nn.nlayers() + 1, *bitwidth.last().unwrap());
    if bitwidth[0] == 0 {
        Error::exit(&cmd.error(ErrorKind::InvalidValue, "Input bitwidth cannot be 0"));
    }

    // Replace 0s with the previous value.
    for i in 1..bitwidth.len() {
        if bitwidth[i] == 0 {
            bitwidth[i] = bitwidth[i - 1];
        }
    }

    println!("Bitwidth: {:?}", bitwidth);
    println!(
        "# Primes: {:?}",
        bitwidth
            .iter()
            .map(|&w| fancy_circuits::util::primes_with_width(w).len())
            .collect::<Vec<_>>()
    );

    match &cli.command {
        Commands::Bitwidth => {
            let nbits = nn.max_bitwidth(&tests)?;
            for (layerno, nbits) in nbits.into_iter().enumerate() {
                println!("Layer {}: {} bits", layerno, nbits);
            }
        }
        Commands::Direct => {
            nn.plaintext_accuracy_test(&tests, &labels)?;
        }
        Commands::Dummy => {
            Channel::with(std::io::empty(), |channel| {
                let mut dummy = Dummy::new();
                nn.boolean_accuracy_test::<DummyVal, Dummy>(
                    &mut dummy, &tests, &labels, &bitwidth, cli.secret, channel,
                )?;
                Ok(())
            })
            .map_err(|e| swanky_error!(SwankyErrorKind::OtherError, "Accuracy test failed: {e}"))?;
        }
        Commands::Bench { niters } => {
            bench(&nn, &tests, &bitwidth, *niters, cli.secret)
                .map_err(|e| swanky_error!(SwankyErrorKind::OtherError, "Benchmark failed: {e}"))?;
        }
    }
    Ok(())
}

/// Run benchmarks on the given neural network and its associated parameters.
pub fn bench(
    nn: &NeuralNet,
    inputs: &[Array3<i64>],
    bitwidth: &[usize],
    niters: usize,
    secret_weights: bool,
) -> swanky_error::Result<()> {
    nn.analyze_binary(bitwidth, secret_weights)
        .map_err(|e| swanky_error!(SwankyErrorKind::OtherError, "Binary informer failed: {e}"))?;

    let total_time = Instant::now();

    for _ in 0..niters {
        nn.eval_roundtrip_binary(&inputs[0], bitwidth, secret_weights)
            .map_err(|e| {
                swanky_error!(SwankyErrorKind::OtherError, "Binary evaluation failed: {e}")
            })?;
    }

    println!(
        "streaming took {:.2?} over {niters} iterations",
        total_time.elapsed()
    );

    Ok(())
}
