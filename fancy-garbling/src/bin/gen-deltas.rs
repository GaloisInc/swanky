extern crate fancy_garbling;

use fancy_garbling::{AllWire, WireLabel};
use std::collections::HashMap;

fn main() {
    let mut deltas = HashMap::new();
    let mut rng = rand::thread_rng();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => usage_and_exit(),
            q => {
                match q.parse::<u16>() {
                    Ok(q) => {
                        // Generate the delta
                        deltas.insert(q, AllWire::rand_delta(&mut rng, q));
                    }
                    _ => {
                        println!("Error parsing \"{}\", number expected", q);
                        usage_and_exit();
                    }
                }
            }
        }
    }
    println!("{}", serde_json::to_string(&deltas).unwrap());
}

fn usage_and_exit() {
    println!("arguments: space-separated list of moduli to generate deltas for");
    println!("outputs: JSON consisting of moduli and deltas");
    std::process::exit(0);
}
