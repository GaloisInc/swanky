use std::cmp::{max, Ordering};
use std::env;

fn gcd_in_clear(a: u128, b: u128, upper_bound: u128) -> u128 {
    let mut r_1: u128 = a;
    let mut r_2 = b;
    for _ in 0..upper_bound {
        match r_1.cmp(&r_2) {
            Ordering::Greater => r_1 -= r_2,
            Ordering::Less => r_2 -= r_1,
            Ordering::Equal => return r_1,
        }
    }

    r_1
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let gb_value: u128 = args[1].parse().unwrap();
    let ev_value: u128 = args[2].parse().unwrap();
    let upper_bound: u128 = max(gb_value, ev_value);

    println!(
        "GCD({}, {}) = {}",
        gb_value,
        ev_value,
        gcd_in_clear(gb_value, ev_value, upper_bound)
    );
}
