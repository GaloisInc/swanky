use std::io::Write;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/sieve_ir.fbs");
    println!("cargo:rerun-if-changed=src/sieve_ir_generated.rs");
    let cache_key = blake3::keyed_hash(
        blake3::hash(b"v1 fbs compilation for mac n'cheese sieve compiler").as_bytes(),
        &std::fs::read("src/sieve_ir.fbs").unwrap(),
    )
    .to_hex();

    let cache_key = cache_key.as_str();
    let generated = std::fs::read_to_string("src/sieve_ir_generated.rs").unwrap();
    if !generated.contains(cache_key) {
        std::env::set_var("PWD", std::env::current_dir().unwrap());
        let was_successful = Command::new("flatc")
            .arg("-o")
            .arg("src/")
            .arg("--rust")
            .arg("src/sieve_ir.fbs")
            .status()
            .unwrap()
            .success();
        assert!(was_successful);
        let generated = std::fs::read_to_string("src/sieve_ir_generated.rs").unwrap();
        std::fs::write(
            "src/sieve_ir_generated.rs",
            format!("#![cfg_attr(rustfmt, rustfmt_skip)]\n{generated}\n// Cache key {cache_key}\n")
                .as_bytes(),
        )
        .unwrap();
    }
}
