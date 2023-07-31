use ff_codegen::{PrimeFieldCodegen, ReprEndianness::Little};
use num_bigint::BigUint;
use sha2::Digest;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;
fn to_hex(buf: &[u8]) -> String {
    let mut out = String::new();
    for byte in buf {
        write!(out, "{:x}", byte).unwrap();
    }
    out
}

fn main() {
    let requests = vec![
        PrimeFieldCodegen {
            ident: "F384p",
            is_pub: true,
            modulus: "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
            generator: "19",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F384q",
            is_pub: true,
            modulus: "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643",
            generator: "19",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F128p",
            is_pub: true,
            modulus: "340282366920938463463374607431768211297",
            generator: "5",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Secp256k1",
            is_pub: true,
            modulus: "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            generator: "3",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Secp256k1order",
            is_pub: true,
            modulus: "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            generator: "7",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F256p",
            is_pub: true,
            modulus: "115792089210356248762697446949407573530086143415290314195533631308867097853951",
            generator: "6",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Fbls12381",
            is_pub: true,
            modulus: "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            generator: "7",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Fbn254",
            is_pub: true,
            modulus: "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            generator: "5",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F2e19x3e26",
            is_pub: true,
            modulus: "1332669751402954753",
            generator: "7",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F400p",
            is_pub: true,
            modulus: "2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747492783",
            generator: "5",
            endianness: Little,
        },
    ];
    let cache_dir = if let Ok(swanky_cache_dir) = std::env::var("SWANKY_CACHE_DIR") {
        let cache_dir = Path::new(&swanky_cache_dir).join("finite-field-codegen-v1");
        std::fs::create_dir_all(&cache_dir).unwrap();
        Some(cache_dir)
    } else {
        None
    };
    let out_dir = Path::new(&std::env::var("OUT_DIR").unwrap()).to_path_buf();
    let cache_key = {
        let mut h = sha2::Sha256::new();
        h.update(std::fs::read(std::env::current_exe().unwrap()).unwrap());
        h.finalize()
    };
    let cache_entry = cache_dir.map(|cache_dir| cache_dir.join(to_hex(&cache_key)));
    let outputs = if let Some(cache_entry) = cache_entry
        .as_ref()
        .filter(|cache_entry| cache_entry.exists())
    {
        let mut outputs = HashMap::<String, String>::new();
        for entry in std::fs::read_dir(cache_entry).unwrap() {
            let entry = entry.unwrap();
            outputs.insert(
                entry.file_name().to_str().unwrap().to_string(),
                std::fs::read_to_string(entry.path()).unwrap(),
            );
        }
        outputs
    } else {
        let outputs = Mutex::new(HashMap::<String, String>::new());
        let queue = Mutex::new(requests);
        std::thread::scope(|scope| {
            for _ in 0..num_cpus::get().max(1) {
                scope.spawn(|| {
                    while let Some(mut cg) = {
                        let mut guard = queue.lock().unwrap();
                        let out = guard.pop();
                        std::mem::drop(guard);
                        out
                    } {
                        let filename = format!("ff-{}.rs", cg.ident);
                        cg.ident = "Internal";
                        let mut out = String::new();
                        write!(out, "{cg}").unwrap();
                        write!(
                            out,
                            "#[cfg(test)] pub(super) const MODULUS_STRING: &str = {:?};",
                            cg.modulus
                        )
                        .unwrap();
                        write!(
                            out,
                            "pub(super) const MODULUS_BYTES: &[u8] = &{:?};",
                            BigUint::from_str(cg.modulus)
                                .unwrap()
                                .to_bytes_le()
                                .as_slice()
                        )
                        .unwrap();
                        write!(
                            out,
                            "#[cfg(test)] pub(super) const GENERATOR_STRING: &str = {:?};",
                            cg.generator
                        )
                        .unwrap();
                        outputs.lock().unwrap().insert(filename, out);
                    }
                });
            }
        });
        outputs.into_inner().unwrap()
    };
    for (k, v) in outputs.iter() {
        std::fs::write(&out_dir.join(k), v.as_bytes()).unwrap();
    }
    if let Some(cache_entry) = cache_entry
        .as_ref()
        .filter(|cache_entry| !cache_entry.exists())
    {
        let tmpdir = tempfile::TempDir::new_in(cache_entry.parent().unwrap()).unwrap();
        for (k, v) in outputs.iter() {
            std::fs::write(&tmpdir.path().join(k), v.as_bytes()).unwrap();
        }
        std::fs::rename(tmpdir.into_path(), cache_entry).unwrap();
    }
    println!("cargo:rerun-if-changed=build.rs");
}
