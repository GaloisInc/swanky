#![feature(test, duration_as_u128)]
extern crate fancy_garbling;

extern crate test;
use std::time::{Duration, SystemTime};

// use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Lines};

use fancy_garbling::high_level::Bundler;
use fancy_garbling::numbers;
use fancy_garbling::circuit::{Builder, Ref};
use fancy_garbling::garble::garble_full;
use fancy_garbling::util::IterToVec;

const WEIGHTS_FILE  : &str = "../dinn/weights-and-biases/txt_weights.txt";
const BIASES_FILE   : &str = "../dinn/weights-and-biases/txt_biases.txt";
const IMAGES_FILE   : &str = "../dinn/weights-and-biases/txt_img_test.txt";
const LABELS_FILE   : &str = "../dinn/weights-and-biases/txt_labels.txt";

const TOPOLOGY: [usize; 3] = [256, 30, 10];
// const NIMAGES: usize = 10000;
const NIMAGES: usize = 1000;
const NLAYERS: usize = 2;

pub fn main() {
    let mut run_benches = false;
    let mut run_tests = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "bench" => run_benches = true,
            "test" => run_tests = true,
            _ => panic!("unknown arg {}", arg),
        }
    }

    let q = numbers::modulus_with_width(10);
    println!("q={}", q);

    let weights: Vec<Vec<Vec<u128>>> = read_weights(q);
    let biases:  Vec<Vec<u128>>      = read_biases(q);
    let images:  Vec<Vec<u128>>      = read_images(q);
    let labels:  Vec<usize>          = read_labels();

    let bun = build_circuit(q, &weights, &biases, false);

    if run_benches {
        println!("running garble/eval benchmark");

        let mut garble_time = Duration::new(0,0);
        let ntests = 16;
        for _ in 0..ntests {
            let start = SystemTime::now();
            let (circ, consts) = bun.borrow();
            let (gb,_) = garble_full(circ, consts);
            test::black_box(gb);
            garble_time += SystemTime::now().duration_since(start).unwrap();
        }
        garble_time /= ntests;

        let (circ, consts) = bun.borrow();
        let (gb,ev) = garble_full(circ, consts);

        let inp = gb.encode(&bun.encode(&images[0]));

        let mut eval_time = Duration::new(0,0);
        for _ in 0..ntests {
            let start = SystemTime::now();
            let res = ev.eval(bun.borrow_circ(), &inp);
            test::black_box(res);
            eval_time += SystemTime::now().duration_since(start).unwrap();
        }
        eval_time /= ntests;

        println!("garbling took {} ms", garble_time.as_millis());
        println!("eval took {} ms", eval_time.as_millis());
        println!("size: {} ciphertexts", ev.size());

    }

    if run_tests {
        println!("running plaintext accuracy evaluation");

        let mut errors = 0;

        for (img_num, img) in images.iter().enumerate() {
            if img_num % 100 == 0 {
                println!("{}/{} {} errors ({}%)", img_num, NIMAGES, errors, 100.0 * (1.0 - errors as f32 / NIMAGES as f32));
            }

            let inp = bun.encode(img);

            let (circ, consts) = bun.borrow();
            let raw = circ.eval_full(&inp, consts);
            let res = bun.decode(&raw);

            let res: Vec<i32> = res.into_iter().map(|x| from_mod_q(q,x)).collect();

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
}

////////////////////////////////////////////////////////////////////////////////
// circuit creation

fn build_circuit(q: u128, weights: &Vec<Vec<Vec<u128>>>, biases: &Vec<Vec<u128>>, secret_weights: bool) -> Bundler {
    let mut b = Bundler::new();
    // let nn_biases = vec![b.inputs(q, TOPOLOGY[1]), b.inputs(q, TOPOLOGY[2])];
    let nn_inputs = b.inputs(q, TOPOLOGY[0]);

    let mut layer_outputs = Vec::new();
    let mut layer_inputs;

    for layer in 0..TOPOLOGY.len()-1 {
        if layer == 0 {
            layer_inputs = nn_inputs.clone();
        } else {
            layer_inputs  = layer_outputs;
            layer_outputs = Vec::new();
        }

        let nin  = TOPOLOGY[layer];
        let nout = TOPOLOGY[layer+1];

        for j in 0..nout {
            let mut x = b.constant(biases[layer][j], q);
            for i in 0..nin {
                let y;
                if secret_weights {
                    y = b.secret_cmul(layer_inputs[i], weights[layer][i][j]);
                } else {
                    y = b.cmul(layer_inputs[i], weights[layer][i][j]);
                }
                x = b.add(x, y);
            }
            layer_outputs.push(x);
        }

        if layer == 0 {
            layer_outputs = layer_outputs.into_iter().map(|x| {
                let ms = vec![2,2,2,42];
                let r = b.sgn(x, &ms);
                b.zero_one_to_one_negative_one(r, q)
            }).collect();
        }
    }

    for out in layer_outputs.into_iter() {
        b.output(out);
    }
    b
}

// for comparison
fn build_boolean_circuit(weights: &Vec<Vec<Vec<u128>>>, biases: &Vec<Vec<u128>>) -> Builder {
    let mut b = Builder::new();
    let nbits = 10;

    let nn_biases = vec![
        (0..TOPOLOGY[1]).map(|_| b.inputs(2,nbits)).to_vec(),
        (0..TOPOLOGY[2]).map(|_| b.inputs(2,nbits)).to_vec(),
    ];

    let nn_inputs = (0..TOPOLOGY[0]).map(|_| b.inputs(2,nbits)).to_vec();

    let mut layer_outputs = Vec::new();
    let mut layer_inputs;

    for layer in 0..TOPOLOGY.len()-1 {
        if layer == 0 {
            layer_inputs = nn_inputs.clone();
        } else {
            layer_inputs  = layer_outputs;
            layer_outputs = Vec::new();
        }

        let nin  = TOPOLOGY[layer];
        let nout = TOPOLOGY[layer+1];

        for j in 0..nout {
            let mut x = to_bit_consts(&mut b, biases[layer][j]);
            for i in 0..nin {
                // let y = b.cmul(layer_inputs[i], weights[layer][i][j]);
                // x = b.add(x, y);
            }
            layer_outputs.push(x);
        }

    //     if layer == 0 {
    //         layer_outputs = layer_outputs.into_iter().map(|x| {
    //             let ms = vec![5,205];
    //             let r = b.sgn(x, &ms);
    //             b.zero_one_to_one_negative_one(r, q)
    //         }).collect();
    //     }
    }

    for out in &layer_outputs {
        b.outputs(out);
    }
    b
}

fn to_bit_consts(b: &mut Builder, x: u128) -> Vec<Ref> {
    unimplemented!()
}

// fn multiplex_constants(b: &mut Builder, x: Ref, c1: u128, c2: u128) {
//     let c1_bs = u128_to_bits(c1);
//     let c2_bs = u129_to_bits(c2);

// }

// fn mux_const_bits(b: &mut Builder, x: Ref, c1: bool, c2: bool) -> Ref {
//     if !c1 && c2 {
//         x
//     } else if c1 && !c2 {
//         b.negate(x)
//     } else if !c1 && !c2 {
//         b.cmul(0)
//     } else {
//         b.project
//     }
// }

////////////////////////////////////////////////////////////////////////////////
// boilerplate io stuff

fn get_lines(file: &str) -> Lines<BufReader<File>> {
    let f = File::open(file).expect("file not found");
    let r = BufReader::new(f);
    r.lines()
}

fn read_weights(q: u128) -> Vec<Vec<Vec<u128>>> {
    let mut lines = get_lines(WEIGHTS_FILE);
    let mut weights = Vec::with_capacity(NLAYERS);
    for layer in 0..NLAYERS {
        let nin  = TOPOLOGY[layer];
        let nout = TOPOLOGY[layer+1];
        weights.push(Vec::with_capacity(nin));
        for i in 0..nin {
            weights[layer].push(Vec::with_capacity(nout));
            for _ in 0..nout {
                let l = lines.next().expect("no more lines").expect("couldnt read a line");
                let w = l.parse().expect("couldnt parse");
                weights[layer][i].push(to_mod_q(q, w));
            }
        }
    }
    weights
}

fn read_biases(q: u128) -> Vec<Vec<u128>> {
    let mut lines = get_lines(BIASES_FILE);
    let mut biases = Vec::with_capacity(NLAYERS);
    for layer in 0..NLAYERS {
        let nout = TOPOLOGY[layer+1];
        biases.push(Vec::with_capacity(nout));
        for _ in 0..nout {
            let l = lines.next().expect("no more lines").expect("couldnt read a line");
            let w = l.parse().expect("couldnt parse");
            biases[layer].push(to_mod_q(q,w));
        }
    }
    biases
}

fn read_images(q: u128) -> Vec<Vec<u128>> {
    let mut lines = get_lines(IMAGES_FILE);
    let mut images = Vec::with_capacity(NIMAGES);
    for i in 0..NIMAGES {
        images.push(Vec::new());
        for _ in 0..TOPOLOGY[0] {
            let l = lines.next().expect("no more lines").expect("couldnt read a line");
            let w = l.parse().expect("couldnt parse");
            images[i].push(to_mod_q(q,w));
        }
    }
    images
}

fn read_labels() -> Vec<usize> {
    get_lines(LABELS_FILE)
        .map(|line| line.expect("couldnt read").parse().expect("couldnt parse"))
        .collect()
}

fn to_mod_q(q: u128, x: i16) -> u128 {
    ((q as i128 + x as i128) % q as i128) as u128
}

fn from_mod_q(q: u128, x: u128) -> i32 {
    if x > q/2 {
        (q as i128 / 2 - x as i128) as i32
    } else {
        x as i32
    }
}
