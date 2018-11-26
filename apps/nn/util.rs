use std::io::{BufReader, Lines};
use std::io::prelude::*;
use std::fs::File;

pub fn get_lines(file: &str) -> Lines<BufReader<File>> {
    let f = File::open(file).expect("file not found");
    let r = BufReader::new(f);
    r.lines()
}

pub fn to_mod_q(q: u128, x: i32) -> u128 {
    ((q as i128 + x as i128) % q as i128) as u128
}

pub fn from_mod_q(q: u128, x: u128) -> i32 {
    if x > q/2 {
        (q as i128 / 2 - x as i128) as i32
    } else {
        x as i32
    }
}

pub fn twos_complement_negate(x: u128, nbits: usize) -> u128 {
    let mask = (1<<nbits)-1;
    ((!x) & mask) + 1
}

pub fn i32_to_twos_complement(x: i32, nbits: usize) -> u128 {
    if x >= 0 {
        x as u128
    } else {
        twos_complement_negate((-x) as u128, nbits)
    }
}

