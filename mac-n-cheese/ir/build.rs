use std::io::Write;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/compilation_format.fbs");
    println!("cargo:rerun-if-changed=src/compilation_format_generated.rs");
    let cache_key = blake3::keyed_hash(
        blake3::hash(b"v1 fbs compilation for mac n'cheese").as_bytes(),
        &std::fs::read("src/compilation_format.fbs").unwrap(),
    )
    .to_hex();

    let cache_key = cache_key.as_str();
    if !std::fs::read_to_string("src/compilation_format_generated.rs")
        .unwrap()
        .contains(cache_key)
    {
        std::env::set_var("PWD", std::env::current_dir().unwrap());
        let was_successful = Command::new("flatc")
            .arg("-o")
            .arg("src")
            .arg("--rust")
            .arg("src/compilation_format.fbs")
            .status()
            .unwrap()
            .success();
        assert!(was_successful);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open("src/compilation_format_generated.rs")
            .unwrap();
        f.write_all(format!("\n// Cache key {cache_key}\n").as_bytes())
            .unwrap();
    }
}
