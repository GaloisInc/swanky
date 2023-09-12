/*!
Cli utilities.

*/
use clap::Parser;
use ocelot::svole::{
    LpnParams, LPN_EXTEND_LARGE, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_SETUP_LARGE,
    LPN_SETUP_MEDIUM, LPN_SETUP_SMALL,
};
use serde::Deserialize;
use std::path::PathBuf;

const DEFAULT_ADDR: &str = "127.0.0.1:5527";
const DEFAULT_THREADS: usize = 1;

/// Lpn params as small, medium or large.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize)]
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

/// Configuration options.
#[derive(Deserialize)]
pub(crate) struct Config {
    /// Select lpn parameter
    pub lpn: LpnSize,

    /// No batching for check_zero
    pub no_batching: bool,
}

/// Cli.
#[derive(Parser)]
#[clap(name = "Diet Mac'n'Cheese")]
#[clap(author = "swanky authors <swanky@galois.com>")]
#[clap(version = "0.1")]
pub(crate) struct Cli {
    /// addr for tcp connection
    #[clap(default_value_t = DEFAULT_ADDR.to_string(), short, long, help = "\
    Address for tcp connection
    When used with --threads N, it expects as many addresses as threads,
    the connection addresses can be listed separated with a comma as --addr \"127.0.0.1:8000,127.0.0.1:8001\".
    If only one \"ADDR:PORT\" is provided then new addresses are created automatically,
    incrementing the port number to match the number of threads.")]
    pub connection_addr: String,

    /// Text
    #[arg(long)]
    pub text: bool,

    /// instance path
    #[clap(long)]
    pub instance: PathBuf,

    /// relation path
    #[clap(long)]
    pub relation: PathBuf,

    /// Config file for internal options.
    #[clap(long)]
    pub config: PathBuf,

    /// witness path
    #[clap(long)]
    pub witness: Option<PathBuf>,

    /// number of threads
    #[clap(long, default_value_t = DEFAULT_THREADS)]
    pub threads: usize,
}
