#![feature(test, duration_as_u128)]

extern crate test;

pub mod neural_net;
pub mod util;
pub mod circuit_tests;
pub mod garbling_benches;

use std::path::Path;
use itertools::Itertools;
use crate::neural_net::NeuralNet;

const BIT_WIDTH: usize = 15;
const NTESTS: usize = 16; // number of iterations of bench

pub fn main() {
    let args = std::env::args().skip(1).collect_vec();
    assert!(args.len() > 0, "directory required!");

    let dir = Path::new(&args[0]);
    assert!(dir.is_dir(), "{} is not a directory!", dir.to_str().unwrap());

    let nn_path = dir.join(Path::new("model.json"));
    let tests_path = dir.join(Path::new("tests.csv"));
    let labels_path = dir.join(Path::new("labels.csv"));

    assert!(nn_path.is_file(), "{} does not exist!", nn_path.to_str().unwrap());
    assert!(tests_path.is_file(), "{} does not exist!", tests_path.to_str().unwrap());
    assert!(labels_path.is_file(), "{} does not exist!", labels_path.to_str().unwrap());

    let mut boolean = false;
    let mut run_bench = false;
    let mut run_tests = false;
    let mut secret_weights = false;
    let mut direct_eval = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-bench"     => run_bench = true,
            "-test"      => run_tests = true,
            "-boolean"   => boolean = true,
            "-secret"    => secret_weights = true,
            "-eval"      => direct_eval = true,
            _ => panic!("unknown arg {}! allowed flags: -bench -test -boolean -secret -eval", arg),
        }
    }

    let nn = NeuralNet::from_json(nn_path.to_str().unwrap());
    println!("neural net topology: {:?}", nn.topology);

    let tests = read_tests(tests_path.to_str().unwrap());
    let labels = read_labels(labels_path.to_str().unwrap());

    if direct_eval {
        nn.test(&tests, &labels);
    }

    if run_bench {
        if boolean {
            garbling_benches::bench_bool_garbling(&nn, &tests[0], BIT_WIDTH, NTESTS, secret_weights);
        } else {
            garbling_benches::bench_arith_garbling(&nn, &tests[0], BIT_WIDTH, NTESTS, secret_weights);
        }
    }

    if run_tests {
        if boolean {
            circuit_tests::test_bool_circuit(&nn, &tests, &labels, BIT_WIDTH, secret_weights);
        } else {
            circuit_tests::test_arith_circuit(&nn, &tests, &labels, BIT_WIDTH, secret_weights);
        }
    }
}

fn read_tests(filename: &str) -> Vec<Vec<i64>> {
    util::get_lines(filename).map(|line| {
        line.unwrap().split(",").map(|s| s.parse().expect("couldn't parse!")).collect()
    }).collect()
}

fn read_labels(filename: &str) -> Vec<usize> {
    util::get_lines(filename).map(|line| {
        let mut max_val = 0;
        let mut winner = 0;
        line.unwrap().split(",")
            .map(|s| s.parse::<usize>().expect("couldn't parse!"))
            .enumerate()
            .for_each(|(i,v)| {
                if v > max_val {
                    max_val = v;
                    winner = i;
                }
            });
        winner
    }).collect()
}
