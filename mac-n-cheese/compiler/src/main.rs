#![deny(unused_must_use)]

use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
/*#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;*/

mod aes_example;
mod sieve_compiler;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile the AES example benchmark.
    CompileAesBenchmark(aes_example::AesArgs),
    CompileSieve(sieve_compiler::SieveArgs),
}

fn setup_panic_handler() {
    // a panic on any thread will kill the process.
    let orig = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        orig(info);
        std::process::exit(1);
    }));
}

fn main() -> eyre::Result<()> {
    /*let profiler = dhat::Profiler::builder().trim_backtraces(None).build();
    std::thread::spawn(move || {
        TcpListener::bind("localhost:9999")
            .unwrap()
            .accept()
            .unwrap();
        std::mem::drop(profiler);
    });*/
    color_eyre::install()?;
    setup_panic_handler();
    match Cli::parse().command {
        Commands::CompileAesBenchmark(args) => aes_example::aes_main(args),
        Commands::CompileSieve(args) => sieve_compiler::sieve_compiler_main(args),
    }
}
