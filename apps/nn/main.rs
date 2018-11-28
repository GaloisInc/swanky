#![feature(test, duration_as_u128)]
extern crate fancy_garbling;
extern crate itertools;
extern crate rand;
extern crate test;
extern crate serde;
extern crate serde_json;

pub mod neural_net;
pub mod util;

use neural_net::NeuralNet;
use itertools::Itertools;

// XXX factor out benchmark and testing from dinn

pub fn main() {
    // TODO need real arg parsing

    let args = std::env::args().skip(1).collect_vec();
    assert!(args[0].ends_with(".json"));
    let _nn = NeuralNet::from_json(&args[0]);
}
