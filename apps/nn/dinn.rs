#![feature(test, duration_as_u128)]
extern crate fancy_garbling;
extern crate itertools;
extern crate rand;
extern crate test;

pub mod neural_net;
pub mod util;

use neural_net::NeuralNet;

use std::time::{Duration, SystemTime};

use fancy_garbling::numbers;
use fancy_garbling::garble::garble;

use itertools::Itertools;

const WEIGHTS_FILE  : &str = "../dinn/weights-and-biases/txt_weights.txt";
const BIASES_FILE   : &str = "../dinn/weights-and-biases/txt_biases.txt";
const IMAGES_FILE   : &str = "../dinn/weights-and-biases/txt_img_test.txt";
const LABELS_FILE   : &str = "../dinn/weights-and-biases/txt_labels.txt";

const TOPOLOGY: [usize; 3] = [256, 30, 10];
// const NIMAGES: usize = 10000;
const NIMAGES: usize = 1000;

const BIT_WIDTH: usize = 10;

const NTESTS: u32 = 16; // number of iterations of bench

pub fn main() {
    let mut boolean = false;

    let mut run_bench = false;
    let mut run_tests = false;

    let mut secret_weights = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "bench"     => run_bench = true,
            "test"      => run_tests = true,
            "boolean"   => boolean = true,
            "secret"    => secret_weights = true,
            _ => panic!("unknown arg {}! allowed commands: bench test boolean secret", arg),
        }
    }

    let nn = NeuralNet::from_dinn_file(WEIGHTS_FILE, BIASES_FILE, &TOPOLOGY);

    let images = read_images(IMAGES_FILE);
    let labels = read_labels(LABELS_FILE);

    if run_bench {
        if boolean {
            bench_bool_garbling(&nn, &images[0], secret_weights);
        } else {
            bench_arith_garbling(&nn, &images[0], secret_weights);
        }
    }

    if run_tests {
        if boolean {
            test_bool_circuit(&nn, &images, &labels, secret_weights);
        } else {
            test_arith_circuit(&nn, &images, &labels, secret_weights);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// tests

fn test_arith_circuit(nn: &NeuralNet, images: &Vec<Vec<i32>>, labels: &[usize], secret_weights: bool) {
    println!("running plaintext accuracy evaluation");
    println!("secret weights={}", secret_weights);

    let q = numbers::modulus_with_width(BIT_WIDTH as u32);
    println!("q={} primes={:?}", q, numbers::factor(q));
    let bun = neural_net::build_circuit(q, nn, secret_weights);

    let mut errors = 0;

    for (img_num, img) in images.iter().enumerate() {
        if img_num % 100 == 0 {
            println!("{}/{} {} errors ({}%)", img_num, NIMAGES, errors, 100.0 * (1.0 - errors as f32 / img_num as f32));
        }

        let circ = bun.borrow_circ();
        let modq_img = img.iter().map(|&i| util::to_mod_q(q,i)).collect_vec();
        let inp = bun.encode(&modq_img);
        let raw = circ.eval(&inp);
        let res = bun.decode(&raw);

        let res: Vec<i32> = res.into_iter().map(|x| util::from_mod_q(q,x)).collect();

        let mut max_val = i32::min_value();
        let mut winner = 0;
        for (i, item) in res.into_iter().enumerate() {
            if item > max_val {
                max_val = item;
                winner = i;
            }
        }

        if winner != labels[img_num] {
            errors += 1;
        }
    }
    println!("errors: {}/{}. accuracy: {}%", errors, NIMAGES, 100.0 * (1.0 - errors as f32 / NIMAGES as f32));
}

fn bench_arith_garbling(nn: &NeuralNet, image: &[i32], secret_weights: bool) { //
    println!("running garble/eval benchmark");
    println!("secret weights={}", secret_weights);

    let q = numbers::modulus_with_width(BIT_WIDTH as u32);
    println!("q={} primes={:?}", q, numbers::factor(q));
    let mut bun = neural_net::build_circuit(q, nn, secret_weights);

    let mut garble_time = Duration::new(0,0);
    for _ in 0..NTESTS {
        let start = SystemTime::now();
        let circ = bun.borrow_circ();
        let gb = garble(circ, &mut rand::thread_rng());
        test::black_box(gb);
        garble_time += SystemTime::now().duration_since(start).unwrap();
    }
    garble_time /= NTESTS;

    let circ = bun.finish();
    let (en,_de,ev) = garble(&circ, &mut rand::thread_rng());

    let img = image.iter().map(|&i| util::to_mod_q(q,i)).collect_vec();
    let inp = en.encode(&bun.encode(&img));

    let mut eval_time = Duration::new(0,0);
    for _ in 0..NTESTS {
        let start = SystemTime::now();
        let res = ev.eval(&circ, &inp);
        test::black_box(res);
        eval_time += SystemTime::now().duration_since(start).unwrap();
    }
    eval_time /= NTESTS;

    println!("garbling took {} ms", garble_time.as_millis());
    println!("eval took {} ms", eval_time.as_millis());
    println!("size: {} ciphertexts", ev.size());
}

fn test_bool_circuit(nn: &NeuralNet, images: &Vec<Vec<i32>>, labels: &[usize], secret_weights: bool) {
    let nbits = BIT_WIDTH;
    let circ = neural_net::build_boolean_circuit(nbits, nn, secret_weights);

    println!("noutputs={}", circ.noutputs());
    println!("running plaintext accuracy evaluation for boolean circuit");
    println!("secret weights={}", secret_weights);

    let mut errors = 0;
    for (img_num, img) in images.iter().enumerate() {
        if img_num % 20 == 0 {
            println!("{}/{} {} errors ({}% accuracy)", img_num, NIMAGES, errors, 100.0 * (1.0 - errors as f32 / img_num as f32));
        }

        let inp = img.iter().map(|&x| if x == -1 { 1 } else if x == 1 { 0 } else { panic!("unknown input {}", x) } ).collect_vec();
        let out = circ.eval(&inp);

        let res = out.chunks(nbits).map(|bs| {
            let x = numbers::u128_from_bits(bs);
            util::from_mod_q(1<<nbits, x)
        }).collect_vec();

        let mut max_val = i32::min_value();
        let mut winner = 0;
        for i in 0..res.len() {
            if res[i] > max_val {
                max_val = res[i];
                winner = i;
            }
        }
        if winner != labels[img_num] {
            errors += 1;
        }
    }

    println!("errors: {}/{}. accuracy: {}%", errors, NIMAGES, 100.0 * (1.0 - errors as f32 / NIMAGES as f32));
}

fn bench_bool_garbling(nn: &NeuralNet, image: &[i32], secret_weights: bool) {
    println!("running garble/eval benchmark for boolean circuit");
    println!("secret weights={}", secret_weights);

    let nbits = BIT_WIDTH;
    let circ = neural_net::build_boolean_circuit(nbits, nn, secret_weights);

    let mut garble_time = Duration::new(0,0);
    for _ in 0..NTESTS {
        let start = SystemTime::now();
        let gb = garble(&circ, &mut rand::thread_rng());
        test::black_box(gb);
        garble_time += SystemTime::now().duration_since(start).unwrap();
    }
    garble_time /= NTESTS;

    let (en,_de,ev) = garble(&circ, &mut rand::thread_rng());

    let img = image.iter().map(|&x| if x == -1 { 1 } else if x == 1 { 0 } else { panic!("unknown input {}", x) } ).collect_vec();
    let inp = en.encode(&img);

    let mut eval_time = Duration::new(0,0);
    for _ in 0..NTESTS {
        let start = SystemTime::now();
        let res = ev.eval(&circ, &inp);
        test::black_box(res);
        eval_time += SystemTime::now().duration_since(start).unwrap();
    }
    eval_time /= NTESTS;

    println!("garbling took {} ms", garble_time.as_millis());
    println!("eval took {} ms", eval_time.as_millis());
    println!("size: {} ciphertexts", ev.size());
}


////////////////////////////////////////////////////////////////////////////////
// io stuff

fn read_images(images_file: &str) -> Vec<Vec<i32>> {
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

////////////////////////////////////////////////////////////////////////////////
// math stuff

