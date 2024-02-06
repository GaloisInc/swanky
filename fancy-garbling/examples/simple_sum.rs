use std::env;

fn sum_in_clear(gb_value: u128, ev_value: u128) -> u128 {
    gb_value + ev_value
}
fn main() {
    let args: Vec<_> = env::args().collect();
    let gb_value: u128 = args[1].parse().unwrap();
    let ev_value: u128 = args[2].parse().unwrap();

    println!(
        "Sum({} + {}) = {}",
        gb_value,
        ev_value,
        sum_in_clear(gb_value, ev_value)
    );
}
