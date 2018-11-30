#![feature(test, duration_as_u128)]
extern crate fancy_garbling;
extern crate itertools;
extern crate rand;
extern crate test;
extern crate serde_json;

pub mod neural_net;
pub mod util;
pub mod circuit_tests;
pub mod garbling_benches;

use neural_net::NeuralNet;

const WEIGHTS_FILE  : &str = "../dinn/weights-and-biases/txt_weights.txt";
const BIASES_FILE   : &str = "../dinn/weights-and-biases/txt_biases.txt";
const IMAGES_FILE   : &str = "../dinn/weights-and-biases/txt_img_test.txt";
const LABELS_FILE   : &str = "../dinn/weights-and-biases/txt_labels.txt";

const TOPOLOGY: [usize; 3] = [256, 30, 10];
const NIMAGES: usize = 10000;
// const NIMAGES: usize = 1000;

const BIT_WIDTH: usize = 10;
const NTESTS: usize = 16; // number of iterations of bench

pub fn main() {
    let mut boolean = false;
    let mut run_bench = false;
    let mut run_tests = false;
    let mut secret_weights = false;
    let mut direct_eval = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-bench"     => run_bench = true,
            "-test"      => run_tests = true,
            "-boolean"   => boolean = true,
            "-secret"    => secret_weights = true,
            "-eval"      => direct_eval = true,
            _ => panic!("unknown arg {}! allowed commands: -bench -test -boolean -secret -eval", arg),
        }
    }

    let nn = NeuralNet::from_dinn_file(WEIGHTS_FILE, BIASES_FILE, &TOPOLOGY);

    let images = read_images(IMAGES_FILE);
    let labels = read_labels(LABELS_FILE);

    if direct_eval {
        nn.test(&images, &labels);
    }

    if run_bench {
        if boolean {
            garbling_benches::bench_bool_garbling(&nn, &images[0], BIT_WIDTH, NTESTS, secret_weights);
        } else {
            garbling_benches::bench_arith_garbling(&nn, &images[0], BIT_WIDTH, NTESTS, secret_weights);
        }
    }

    if run_tests {
        if boolean {
            circuit_tests::test_bool_circuit(&nn, &images, &labels, BIT_WIDTH, secret_weights);
        } else {
            circuit_tests::test_arith_circuit(&nn, &images, &labels, BIT_WIDTH, secret_weights);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// io stuff

fn read_images(images_file: &str) -> Vec<Vec<i64>> {
    let mut lines = util::get_lines(images_file);
    let mut images = Vec::with_capacity(NIMAGES);
    for i in 0..NIMAGES {
        images.push(Vec::new());
        for _ in 0..TOPOLOGY[0] {
            let l = lines.next().expect("no more lines").expect("couldnt read a line");
            let w = l.parse().expect("couldnt parse");
            images[i].push(w);
        }
    }
    images
}

fn read_labels(labels_file: &str) -> Vec<usize> {
    util::get_lines(labels_file)
        .map(|line| line.expect("couldnt read").parse().expect("couldnt parse"))
        .collect()
}
