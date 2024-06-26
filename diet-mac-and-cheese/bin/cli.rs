/*!
Cli utilities.

*/
use clap::Parser;
use diet_mac_and_cheese::LpnSize;
use eyre::Result;
use serde::Deserialize;
use std::path::PathBuf;

const DEFAULT_ADDR: &str = "127.0.0.1:5527";
const DEFAULT_NO_BATCHING: bool = false;
const DEFAULT_THREADS: usize = 1;
const DEFAULT_THREADS_PER_FIELD: usize = 1;

/// Internal Diet Mac'n'Cheese configurations.
///
/// Use this to add configurable parameters from an optional TOML file.
/// To add a new parameter:
///
/// 1. Name it what you want the TOML key to be
/// 2. Wrap the parameter's type in `Option`. Note that enumerations are OK! We
///    recommend using #[serde(rename_all = "...")] with an appropriate case
///    convention for your use-case (and a matching `Display` instance).
/// 3. Update the `Default` implementation for `Config` to provide
///    `Some(value)` for your parameter. If you can't pick a sensible default,
///    consider making the parameter a required command-line argument instead!
///    We also recommend using a `const` for this value (or a `Default`
///    implementation, if using an `enum` or `struct` - we do have the full
///    power of TOML, after all!)
/// 4. Provide an `unwrap`ping accessor for your parameter. This is safe since
///    the only way to construct a `Config` is with `Default` or via the
///    associated function [`Config::from_toml_file`]. Speaking of...
/// 5. Update `Config::from_toml_file` with an `if let` for your new parameter,
///    which can be modeled after the existing `if let`s.
/// 6. Update the --help text for the configuration path to show the default
///    values in case a config file isn't provided. When possible, do this
///    programmatically so the help text stays up-to-date!
#[derive(Deserialize)]
pub(crate) struct Config {
    /// The LPN size to use for SVOLE.
    lpn: Option<LpnSize>,

    /// If set, do not batch check_zero tasks.
    no_batching: Option<bool>,

    /// The number of threads to use (for SVOLE).
    threads: Option<usize>,

    /// The number of threads per field.
    threads_per_field: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            lpn: Some(LpnSize::default()),
            no_batching: Some(DEFAULT_NO_BATCHING),
            threads: Some(DEFAULT_THREADS),
            threads_per_field: Some(DEFAULT_THREADS_PER_FIELD),
        }
    }
}

impl Config {
    /// Construct a new [`Config`] from a TOML file. Any missing fields are
    /// initialized using the `Default` instance.
    pub fn from_toml_file(toml_file: &PathBuf) -> Result<Self> {
        let mut res = Config::default();

        let toml_contents: Config = toml::from_str(&std::fs::read_to_string(toml_file)?)?;

        if let Some(lpn) = toml_contents.lpn {
            res.lpn = Some(lpn)
        }

        if let Some(no_batching) = toml_contents.no_batching {
            res.no_batching = Some(no_batching)
        }

        if let Some(threads) = toml_contents.threads {
            res.threads = Some(threads)
        }

        if let Some(threads_per_field) = toml_contents.threads_per_field {
            res.threads_per_field = Some(threads_per_field)
        }

        Ok(res)
    }

    /// The SVOLE LPN size.
    pub fn lpn(&self) -> LpnSize {
        self.lpn.unwrap()
    }

    /// The value of the no-batching flag.
    pub fn no_batching(&self) -> bool {
        self.no_batching.unwrap()
    }

    /// The number of threads to use for SVOLE.
    pub fn threads(&self) -> usize {
        self.threads.unwrap()
    }

    /// The number of threads per field
    pub fn threads_per_field(&self) -> usize {
        self.threads_per_field.unwrap()
    }
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

    /// Read circuit files in text format, rather than flatbuffers.
    #[arg(long)]
    pub text: bool,

    /// Evaluate circuits in the clear, instead of in ZK.
    #[clap(default_value_t = false, short, long)]
    pub plaintext: bool,

    /// Config file for internal options.
    #[clap(long, help = format!("\
    Path to an (optional) Diet Mac'n'Cheese configuration file.
    Sets parameters internal to the operation of Diet Mac'n'Cheese that can usually be left as the defaults.
    Presently, the parameters we support (and their defaults) are:
    - lpn = ${}
    - no_batching = ${}
    - threads = ${}
    ", LpnSize::default(), DEFAULT_NO_BATCHING, DEFAULT_THREADS))]
    pub config: Option<PathBuf>,

    /// instance path
    #[clap(long)]
    pub instance: PathBuf,

    /// relation path
    #[clap(long)]
    pub relation: PathBuf,

    /// witness path
    #[clap(long)]
    pub witness: Option<PathBuf>,
}
