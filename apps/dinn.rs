#![feature(test, duration_as_u128)]
extern crate fancy_garbling;

extern crate test;
use std::time::{Duration, SystemTime};

use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Lines};

use fancy_garbling::high_level::Bundler;
use fancy_garbling::numbers;
use fancy_garbling::circuit::{Builder, Ref, Circuit};
use fancy_garbling::garble::garble;
use fancy_garbling::util::IterToVec;

struct NeuralNet {
    weights: Vec<Vec<Vec<i32>>>,
    biases: Vec<Vec<i32>>,
}

const WEIGHTS_FILE  : &str = "../dinn/weights-and-biases/txt_weights.txt";
const BIASES_FILE   : &str = "../dinn/weights-and-biases/txt_biases.txt";
const IMAGES_FILE   : &str = "../dinn/weights-and-biases/txt_img_test.txt";
const LABELS_FILE   : &str = "../dinn/weights-and-biases/txt_labels.txt";

const TOPOLOGY: [usize; 3] = [256, 30, 10];
// const NIMAGES: usize = 10000;
const NIMAGES: usize = 1000;
const NLAYERS: usize = 2;

const BIT_WIDTH: usize = 10;

pub fn main() {
    let mut run_benches = false;
    let mut run_tests = false;
    let mut run_bool_tests = false;
    let mut run_bool_benches = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "bench" => run_benches = true,
            "test" => run_tests = true,
            "bool_test" => run_bool_tests = true,
            "bool_bench" => run_bool_benches = true,
            _ => panic!("unknown arg {}! allowed commands: bench, test, bool_test, bool_bench", arg),
        }
    }

    let nn = NeuralNet::from_file(WEIGHTS_FILE, BIASES_FILE);

    let images = read_images(IMAGES_FILE);
    let labels = read_labels(LABELS_FILE);

    if run_benches      { bench_arith_garbling(&nn, &images[0]); }
    if run_tests        { test_arith_circuit(&nn, &images, &labels); }
    if run_bool_tests   { test_bool_circuit(&nn, &images, &labels); }
    if run_bool_benches { bench_bool_garbling(&nn, &images[0]); }
}

////////////////////////////////////////////////////////////////////////////////
// tests

fn test_arith_circuit(nn: &NeuralNet, images: &Vec<Vec<i32>>, labels: &[usize]) {
    println!("running plaintext accuracy evaluation");

    let q = numbers::modulus_with_width(BIT_WIDTH as u32);
    println!("q={}", q);
    let bun = build_circuit(q, nn, false);

    let mut errors = 0;

    for (img_num, img) in images.iter().enumerate() {
        if img_num % 100 == 0 {
            println!("{}/{} {} errors ({}%)", img_num, NIMAGES, errors, 100.0 * (1.0 - errors as f32 / img_num as f32));
        }

        let circ = bun.borrow_circ();
        let modq_img = img.iter().map(|&i| to_mod_q(q,i)).to_vec();
        let inp = bun.encode(&modq_img);
        let raw = circ.eval(&inp);
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

fn bench_arith_garbling(nn: &NeuralNet, image: &[i32]) {
    println!("running garble/eval benchmark");

    let q = numbers::modulus_with_width(BIT_WIDTH as u32);
    println!("q={}", q);
    let mut bun = build_circuit(q, nn, false);

    let mut garble_time = Duration::new(0,0);
    let ntests = 16;
    for _ in 0..ntests {
        let start = SystemTime::now();
        let circ = bun.borrow_circ();
        let (gb,_) = garble(circ);
        test::black_box(gb);
        garble_time += SystemTime::now().duration_since(start).unwrap();
    }
    garble_time /= ntests;

    let circ = bun.finish();
    let (gb,ev) = garble(&circ);

    let img = image.iter().map(|&i| to_mod_q(q,i)).to_vec();
    let inp = gb.encode(&bun.encode(&img));

    let mut eval_time = Duration::new(0,0);
    for _ in 0..ntests {
        let start = SystemTime::now();
        let res = ev.eval(&circ, &inp);
        test::black_box(res);
        eval_time += SystemTime::now().duration_since(start).unwrap();
    }
    eval_time /= ntests;

    println!("garbling took {} ms", garble_time.as_millis());
    println!("eval took {} ms", eval_time.as_millis());
    println!("size: {} ciphertexts", ev.size());
}

fn test_bool_circuit(nn: &NeuralNet, images: &Vec<Vec<i32>>, labels: &[usize]) {
    let nbits = BIT_WIDTH;
    let circ = build_boolean_circuit(nbits, nn);

    println!("noutputs={}", circ.noutputs());
    println!("running plaintext accuracy evaluation for boolean circuit");

    let mut errors = 0;
    for (img_num, img) in images.iter().enumerate() {
        if img_num % 20 == 0 {
            println!("{}/{} {} errors ({}% accuracy)", img_num, NIMAGES, errors, 100.0 * (1.0 - errors as f32 / img_num as f32));
        }

        let inp = img.iter().map(|&x| if x == -1 { 1 } else if x == 1 { 0 } else { panic!("unknown input {}", x) } ).to_vec();
        let out = circ.eval(&inp);

        let res = out.chunks(nbits).map(|bs| {
            let x = numbers::u128_from_bits(bs);
            from_mod_q(1<<nbits, x)
        }).to_vec();

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

fn bench_bool_garbling(nn: &NeuralNet, image: &[i32]) {
    println!("running garble/eval benchmark for boolean circuit");

    let nbits = BIT_WIDTH;
    let circ = build_boolean_circuit(nbits, nn);

    let mut garble_time = Duration::new(0,0);
    let ntests = 16;
    for _ in 0..ntests {
        let start = SystemTime::now();
        let (gb,_) = garble(&circ);
        test::black_box(gb);
        garble_time += SystemTime::now().duration_since(start).unwrap();
    }
    garble_time /= ntests;

    let (gb,ev) = garble(&circ);

    let img = image.iter().map(|&x| if x == -1 { 1 } else if x == 1 { 0 } else { panic!("unknown input {}", x) } ).to_vec();
    let inp = gb.encode(&img);

    let mut eval_time = Duration::new(0,0);
    for _ in 0..ntests {
        let start = SystemTime::now();
        let res = ev.eval(&circ, &inp);
        test::black_box(res);
        eval_time += SystemTime::now().duration_since(start).unwrap();
    }
    eval_time /= ntests;

    println!("garbling took {} ms", garble_time.as_millis());
    println!("eval took {} ms", eval_time.as_millis());
    println!("size: {} ciphertexts", ev.size());
}

////////////////////////////////////////////////////////////////////////////////
// circuit creation

fn build_circuit(q: u128, nn: &NeuralNet, secret_weights: bool) -> Bundler {
    let mut b = Bundler::new();
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
            let bias = to_mod_q(q, nn.bias(layer,j));
            let mut x = b.secret_constant(bias, q);
            for i in 0..nin {
                let y;
                let weight = to_mod_q(q, nn.weight(layer,i,j));
                if secret_weights {
                    y = b.secret_cmul(layer_inputs[i], weight);
                } else {
                    y = b.cmul(layer_inputs[i], weight);
                }
                x = b.add(x, y);
            }
            layer_outputs.push(x);
        }

        if layer == 0 {
            layer_outputs = layer_outputs.into_iter().map(|x| {
                // let ms = vec![2,2,2,42]; // aprox?
                let ms = vec![2,2,3,54]; // exact?!
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

fn build_boolean_circuit(nbits: usize, nn: &NeuralNet) -> Circuit {
    let mut b = Builder::new();

    // binary inputs with 0 representing -1
    let nn_inputs = (0..TOPOLOGY[0]).map(|_| b.input(2)).to_vec();

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

        let mut acc = Vec::new();

        for j in 0..nout {
            // map the bias values to binary consts
            let bias = i32_to_twos_complement(nn.bias(layer,j), nbits);
            let mut x = numbers::u128_to_bits(bias, nbits).into_iter().map(|bit| b.constant(bit,2)).to_vec();
            for i in 0..nin {
                // hardcode the weights into the circuit
                let w = nn.weight(layer,i,j) as u128;
                let negw = twos_complement_negate(nn.weight(layer,i,j) as u128, nbits);
                let y = multiplex_constants(&mut b, layer_inputs[i], w, negw, nbits);
                x = b.addition_no_carry(&x, &y);
            }
            acc.push(x);
        }

        if layer < TOPOLOGY.len()-2 {
            layer_outputs = acc.into_iter().map(|x| x[nbits-1] ).collect();
        } else {
            for x in acc {
                b.outputs(&x);
            }
        }
    }

    b.finish()
}

fn multiplex_constants(b: &mut Builder, x: Ref, c1: u128, c2: u128, n: usize) -> Vec<Ref> {
    let c1_bs = numbers::to_bits(c1, n);
    let c2_bs = numbers::to_bits(c2, n);
    c1_bs.into_iter().zip(c2_bs.into_iter()).map(|(c1,c2)| mux_const_bits(b, x, c1, c2)).collect()
}

fn mux_const_bits(b: &mut Builder, x: Ref, c1: u16, c2: u16) -> Ref {
    let b1 = c1 > 0;
    let b2 = c2 > 0;

    if !b1 && b2 {
        x
    } else if b1 && !b2 {
        b.negate(x)
    } else if !b1 && !b2 {
        b.constant(0,2)
    } else {
        b.constant(1,2)
    }
}

////////////////////////////////////////////////////////////////////////////////
// NeuralNet methods

impl NeuralNet {
    pub fn from_file(weights_file: &str, biases_file: &str) -> Self {
        let mut lines = get_lines(weights_file);
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
                    weights[layer][i].push(w);
                }
            }
        }

        let mut lines = get_lines(biases_file);
        let mut biases = Vec::with_capacity(NLAYERS);
        for layer in 0..NLAYERS {
            let nout = TOPOLOGY[layer+1];
            biases.push(Vec::with_capacity(nout));
            for _ in 0..nout {
                let l = lines.next().expect("no more lines").expect("couldnt read a line");
                let w = l.parse().expect("couldnt parse");
                biases[layer].push(w);
            }
        }
        Self { weights, biases }
    }

    pub fn weight(&self, layer: usize, i: usize, j: usize) -> i32 {
        self.weights[layer][i][j]
    }

    pub fn bias(&self, layer: usize, j: usize) -> i32 {
        self.biases[layer][j]
    }
}

////////////////////////////////////////////////////////////////////////////////
// io stuff

fn get_lines(file: &str) -> Lines<BufReader<File>> {
    let f = File::open(file).expect("file not found");
    let r = BufReader::new(f);
    r.lines()
}

fn read_images(images_file: &str) -> Vec<Vec<i32>> {
    let mut lines = get_lines(images_file);
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
    get_lines(labels_file)
        .map(|line| line.expect("couldnt read").parse().expect("couldnt parse"))
        .collect()
}

////////////////////////////////////////////////////////////////////////////////
// math stuff

fn to_mod_q(q: u128, x: i32) -> u128 {
    ((q as i128 + x as i128) % q as i128) as u128
}

fn from_mod_q(q: u128, x: u128) -> i32 {
    if x > q/2 {
        (q as i128 / 2 - x as i128) as i32
    } else {
        x as i32
    }
}

fn twos_complement_negate(x: u128, nbits: usize) -> u128 {
    let mask = (1<<nbits)-1;
    ((!x) & mask) + 1
}

fn i32_to_twos_complement(x: i32, nbits: usize) -> u128 {
    if x >= 0 {
        x as u128
    } else {
        twos_complement_negate((-x) as u128, nbits)
    }
}

#[cfg(test)]
mod dinn {
    use super::*;
    use fancy_garbling::rand::Rng;
    use fancy_garbling::circuit::Builder;
    use fancy_garbling::numbers;

    #[test]
    fn multiplex() {
        let mut rng = Rng::new();

        let nbits = 16;
        let mask = (1 << nbits) - 1;

        let c1 = rng.gen_u128() & mask;
        let c2 = rng.gen_u128() & mask;

        let mut b = Builder::new();
        let x = b.input(2);
        let ys = multiplex_constants(&mut b, x, c1, c2, nbits);
        b.outputs(&ys);
        let circ = b.finish();

        let c1_bits = numbers::to_bits(c1, nbits);
        let c2_bits = numbers::to_bits(c2, nbits);

        assert_eq!(circ.eval(&[0]), c1_bits);
        assert_eq!(circ.eval(&[1]), c2_bits);
    }
}
