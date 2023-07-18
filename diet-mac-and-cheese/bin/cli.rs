/*!
Cli utilities.

*/
use clap::{Parser, Subcommand, ValueEnum};
use ocelot::svole::{
    LpnParams, LPN_EXTEND_LARGE, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_SETUP_LARGE,
    LPN_SETUP_MEDIUM, LPN_SETUP_SMALL,
};
use std::path::PathBuf;

const DEFAULT_ADDR: &str = "127.0.0.1:5527";
const DEFAULT_LPN: LpnSize = LpnSize::Medium;

/// Lpn params as small, medium or large.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
pub(crate) enum LpnSize {
    Small,
    Medium,
    Large,
}

/// Map an `LpnSize` to a pair of Lpn parameters for the init and extension phase.
#[allow(dead_code)] // This is _not_ dead code, but the compiler thinks it is (it is used in `dietmc_zki.rs`)
pub(crate) fn map_lpn_size(lpn_param: &LpnSize) -> (LpnParams, LpnParams) {
    match lpn_param {
        LpnSize::Small => {
            return (LPN_SETUP_SMALL, LPN_EXTEND_SMALL);
        }
        LpnSize::Medium => {
            return (LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM);
        }
        LpnSize::Large => {
            return (LPN_SETUP_LARGE, LPN_EXTEND_LARGE);
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum Prover {
    /// Set for prover mode
    Prover {
        /// witness path
        #[clap(long)]
        witness: PathBuf,
    },
}

/// Cli.
#[derive(Parser)]
#[clap(name = "Diet Mac'n'Cheese")]
#[clap(author = "swanky authors <swanky@galois.com>")]
#[clap(version = "0.1")]
pub(crate) struct Cli {
    /// Set addr for tcp connection
    #[clap(default_value_t = DEFAULT_ADDR.to_string(), short, long)]
    pub connection_addr: String,

    /// Select lpn parameter
    #[clap(value_enum, default_value_t = DEFAULT_LPN, long)]
    pub lpn: LpnSize,

    /// Text
    #[arg(long)]
    pub text: bool,

    /// No batching for check_zero
    #[arg(long)]
    pub nobatching: bool,

    /// instance path
    #[clap(long)]
    pub instance: PathBuf,

    /// relation path
    #[clap(long)]
    pub relation: PathBuf,

    #[clap(subcommand)]
    pub command: Option<Prover>,
}
