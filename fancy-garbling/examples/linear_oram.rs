use std::env;

fn ram_in_clear(index: usize, ram: &[u128]) -> u128 {
    ram[index]
}

fn main() {
    let args: Vec<_> = env::args().collect();

    let ev_index: usize = args[1].parse().unwrap();
    let gb_ram_string: String = args[2].parse::<String>().unwrap();
    let gb_ram: Vec<u128> = gb_ram_string
        .split_terminator(['[', ',', ']', ' '])
        .filter(|&x| !x.is_empty())
        .map(|s| s.parse::<u128>().unwrap())
        .collect();

    println!(
        "ORAM(index:{ev_index}, ram:{:?}) = {}",
        gb_ram,
        ram_in_clear(ev_index, &gb_ram)
    );
}
