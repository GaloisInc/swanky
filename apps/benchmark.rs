extern crate fancy_garbling as fg;
extern crate getopts;

use fg::circuit::{Circuit, Builder};
use fg::garble::garble;
use fg::rand::Rng;
use fg::high_level::Bundler;
use fg::numbers::PRIMES;

use std::time::SystemTime;
use std::env;
use std::process::exit;
use getopts::Options;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [OPTIONS]", program);
    print!("{}", opts.usage(&brief));
    exit(0);
}

#[allow(non_snake_case, unused_assignments)]
fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu.");
    opts.optopt("q", "", "The low-level tests modulus.", "LMOD");
    opts.optopt("Q", "", "The high-level tests modulus.", "HMOD");
    opts.optopt("n", "", "Number of iterations.", "N");
    opts.optopt("B", "", "Upper bound number of bits for high-level tests (supercedes -Q).", "NBITS");
    opts.optflag("A", "", "Only test addition.");
    opts.optflag("M", "", "Only test multiplication.");
    opts.optflag("H", "", "Only test high-level operations.");
    opts.optflag("L", "", "Only test low-level operations.");
    let matches = opts.parse(&args[1..]).unwrap();
    if matches.opt_present("h") {
        print_usage(&args[0], opts);
    }

    let mut rng = Rng::new();

    let q = match matches.opt_str("q") {
        Some(s) => s.parse::<u8>().unwrap(),
        None    => rng.gen_prime(),
    };

    let Q = match matches.opt_str("B") {
        Some(s) => {
            let nbits = s.parse::<u32>().unwrap();
            let mut res = 1;
            let mut tmp = res;
            let mut ps: Vec<u8> = PRIMES.iter().cloned().collect();
            for _ in 0..ps.len() {
                let l = ps.len();
                let p = ps.remove(rng.gen_byte() as usize % l);
                tmp = res * p as u128;
                if (tmp >> nbits) > 0 {
                    break;
                } else {
                    res = tmp;
                }
            }
            res
        }

        None => match matches.opt_str("Q") {
            Some(s) => u128::from_str_radix(&s[2..], 16).unwrap(),
            None    => rng.gen_usable_composite_modulus(),
        }
    };

    let n = match matches.opt_str("n") {
        Some(s) => s.parse::<usize>().unwrap(),
        None    => 1000,
    };

    let N = match matches.opt_str("n") {
        Some(s) => s.parse::<usize>().unwrap(),
        None    => 100,
    };

    let x = rng.gen_byte() % q;
    let X = rng.gen_u128() % Q;

    let all_levels = !matches.opt_present("L") && !matches.opt_present("H");
    let all_tests  = !matches.opt_present("A") && !matches.opt_present("M");

    if all_levels || matches.opt_present("L") {
        if all_tests || matches.opt_present("A") {
            test_add_low_level(x,q,n);
        }
        if all_tests || matches.opt_present("M") {
            test_mul_low_level(x,q,n);
        }
    }

    if all_levels || matches.opt_present("H") {
        if all_tests || matches.opt_present("A") {
            test_add_high_level(X,Q,N);
        }
        if all_tests || matches.opt_present("M") {
            test_mul_high_level(X,Q,N);
        }
    }
}

fn test_add_low_level(input: u8, modulus: u8, niter: usize) {
    let mut b = Builder::new();
    let x = b.input(modulus);
    let mut z = x;
    for _ in 0..niter {
        z = b.add(z,x);
    }
    b.output(z);
    let c = b.finish();
    println!("Low Level: TestAdd(x={}, q={}, n={}):", input, modulus, niter);
    test_circuit(&[input], &c);
}

fn test_mul_low_level(input: u8, modulus: u8, niter: usize) {
    let mut b = Builder::new();
    let mut x = b.input(modulus);
    for _ in 0..niter {
        x = b.half_gate(x,x);
    }
    b.output(x);
    let c = b.finish();
    println!("Low Level: TestMul(x={}, q={}, n={}):", input, modulus, niter);
    test_circuit(&[input], &c);
}

fn test_add_high_level(input: u128, modulus: u128, niter: usize) {
    let mut b = Bundler::new(Builder::new());
    let mut x = b.input(modulus);
    for _ in 0..niter {
        x = b.add(x,x);
    }
    b.output(x);
    let c = b.take_builder().finish();
    println!("High Level: TestAdd(x=0x{:x}, q=0x{:x}, n={}):", input, modulus, niter);
    test_circuit(&b.encode(&[input]), &c);
}

fn test_mul_high_level(input: u128, modulus: u128, niter: usize) {
    let mut b = Bundler::new(Builder::new());
    let mut x = b.input(modulus);
    for _ in 0..niter {
        x = b.mul(x,x);
    }
    b.output(x);
    let c = b.take_builder().finish();
    println!("High Level: TestMul(x=0x{:x}, q=0x{:x}, n={}):", input, modulus, niter);
    test_circuit(&b.encode(&[input]), &c);
}

#[allow(non_snake_case)]
fn test_circuit(input: &[u8], c: &Circuit) {
    let mut start = SystemTime::now();
    let (mut gb, ev) = garble(&c);
    println!("\tGarble:\t{}", elapsed_since(&start));
    start = SystemTime::now();
    let X = gb.encode(input);
    let Y = ev.eval(&c, &X);
    gb.decode(&Y);
    println!("\tEval:\t{}\n", elapsed_since(&start));
}

fn elapsed_since(start: &SystemTime) -> String {
    let d = start.elapsed().unwrap();
    let us = d.as_secs() * 1000 + d.subsec_nanos() as u64 / 1_000;
    format!("{} us", us)
}
