use fancy_garbling::{
    BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyReveal,
};

use std::env;

//  The main fancy function which describes the garbled circuit for linear ORAM.
fn fancy_linear_oram<F>(
    f: &mut F,
    ram: Vec<F::Item>,
    query: Vec<F::Item>,
) -> Result<BinaryBundle<F::Item>, F::Error>
where
    F: FancyReveal + Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    //  The bits corresponding to the same value are collected into a single Bundle.
    //  In this example, the garbler has multiple values corresponding to different
    //  element of their RAM. Since each element is of size 128 bits, we chunk the
    //  the garbler's input wires into BinaryBundles of size 128.
    let ram: Vec<BinaryBundle<_>> = ram
        .chunks(128)
        .map(|x_chunk| BinaryBundle::new(x_chunk.to_vec()))
        .collect();
    //  The evaluator's input is a single query, and all their wires are bundled together
    //  into a single BinaryBundle.
    let index: BinaryBundle<_> = BinaryBundle::new(query.to_vec());

    let mut result = f.bin_constant_bundle(0, 128)?;
    let zero = f.bin_constant_bundle(0, 128)?;

    //  We traverse the garbler's RAM one element at a time, and multiplex
    //  the result based on whether the evaluator's query matches the current
    //  index.
    for (i, item) in ram.iter().enumerate() {
        //  The current index is turned into a binary constant bundle.
        let current_index = f.bin_constant_bundle(i as u128, 128)?;
        //  We check if the evaluator's query matches the current index obliviously.
        let mux_bit = f.bin_eq_bundles(&index, &current_index)?;
        //  We use the result of the prior equality check to multiplex by either adding 0 to
        //  the result of the computation and keeping it as is, or adding RAM[i] to it
        //  and updating it. The evaluator's query can only correspond to a single index.
        let mux = f.bin_multiplex(&mux_bit, &zero, item)?;
        result = f.bin_addition_no_carry(&result, &mux)?;
    }

    Ok(result)
}

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
