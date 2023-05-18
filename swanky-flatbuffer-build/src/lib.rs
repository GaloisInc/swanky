use std::{
    io::{Read, Write},
    process::Command,
    str::FromStr,
};

const FLATBUFFER_MIN_VERSION: &str = "flatc version 23.1.21"; // Keep in sync with Cargo.toml
const PREFIX: &[u8] = b"// CACHE KEY ";
const HEADER: &[u8] =
    b"#![cfg_attr(rustfmt, rustfmt_skip)]\n#![allow(clippy::all)]\n#![allow(unused_imports)]\n";

const FLATC_VERSION_MSG: &str =
    "Running `flatc --version' failed. Do you have flatbuffer installed? Or, did you \
    untentionally change a .fbs file or a _generated.rs file?";

fn compute_hash(full_src: &[u8], dst_excluding_cache_key: &[u8]) -> blake3::Hash {
    let hash_key = blake3::hash(b"v2 swanky fbs cache key");
    let mut h = blake3::Hasher::new_keyed(hash_key.as_bytes());
    h.update(blake3::hash(full_src).as_bytes());
    h.update(blake3::hash(dst_excluding_cache_key).as_bytes());
    h.finalize()
}

fn needs_recompile(src: &str, dst: &str) -> bool {
    let src_contents = std::fs::read(src).unwrap();
    let dst_contents = std::fs::read(dst).unwrap_or_default();
    // The prefix on the generated file looks like: "// CACHE KEY <32*2 hex>\n"
    if dst_contents.starts_with(PREFIX) {
        let (observed_hash, rest_of_file) = dst_contents[PREFIX.len()..].split_at(32 * 2 + 1);
        debug_assert_eq!(observed_hash.len(), 32 * 2 + 1);
        let observed_hash = &observed_hash[0..32 * 2]; // Strip off newline.
        let computed_hash = compute_hash(&src_contents, rest_of_file);
        observed_hash != computed_hash.to_hex().as_bytes()
    } else {
        true
    }
}

fn parse_version(version: &str) -> (u32, u32, u32) {
    assert!(
        version.starts_with("flatc version "),
        "flatc --version output {version:?} didn't start with 'flatc version'"
    );
    let version = &version[b"flatc version ".len()..];
    let version = version.trim();
    let parts = version
        .split('.')
        .map(|x| u32::from_str(x).expect(FLATC_VERSION_MSG))
        .collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "{}", FLATC_VERSION_MSG);
    (parts[0], parts[1], parts[2])
}

/// Compile the `.fbs` file at `src` to the `.rs` file at `dst`.
///
/// `src` and `dst` should be relative to the crate root.
///
/// The `dst` file _should_ be checked into the git repo so that only people who modify `.fbs`
/// files need to have the `flatc` compiler installed.
///
/// # Example
/// ```ignore
/// swanky_flatbuffer_build::compile_flatbuffer("foo.fbs", "foo_generated.rs");
/// ```
///
/// # Panics
/// This function will _panic_ on any errors. This is a quick-and-dirty (and wrong) error handling
/// approach. However, we only intend this function to be called from build scripts, so it's not
/// a big problem.
pub fn compile_flatbuffer(src: &str, dst: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-changed={dst}");
    if needs_recompile(src, dst) {
        let src_contents = std::fs::read(src).unwrap();
        std::env::set_var("PWD", std::env::current_dir().unwrap());
        let flatc_version = parse_version(
            &String::from_utf8(
                Command::new("flatc")
                    .arg("--version")
                    .output()
                    .unwrap()
                    .stdout,
            )
            .expect(FLATC_VERSION_MSG),
        );
        let min_flatc_version = parse_version(FLATBUFFER_MIN_VERSION);
        assert!(
            min_flatc_version <= flatc_version,
            "Expected flatc >= {min_flatc_version:?}. Found {flatc_version:?}"
        );
        let tmp = tempfile::tempdir().unwrap();
        let was_successful = Command::new("flatc")
            .arg("-o")
            .arg(tmp.path())
            .arg("--rust")
            .arg("--warnings-as-errors")
            .arg(src)
            .status()
            .unwrap()
            .success();
        assert!(was_successful, "Running flatc failed");
        let tmp_contents = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(tmp_contents.len(), 1);
        let mut generated = HEADER.to_vec();
        std::fs::File::open(tmp_contents[0].path())
            .unwrap()
            .read_to_end(&mut generated)
            .unwrap();
        let hash = compute_hash(&src_contents, &generated);
        let mut out = std::fs::File::create(dst).unwrap();
        out.write_all(PREFIX).unwrap();
        out.write_all(hash.to_hex().as_bytes()).unwrap();
        out.write_all(b"\n").unwrap();
        out.write_all(&generated).unwrap();
        out.flush().unwrap();
        std::mem::drop(out);
        assert!(!needs_recompile(src, dst));
    } else {
        eprintln!("Re-using flatbuffer compilation cache for src={src:?}, dst={dst:?}");
    }
}
