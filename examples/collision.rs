use fancy_garbling::fancy::{Fancy, BundleGadgets, HasModulus};
use itertools::Itertools;
use fancy_garbling::garble::bench;

fn collision<W,F>(f: &mut F, nbits: usize, time_slices: usize)
    where F: Fancy<Item=W>, W: Clone + Default + HasModulus
{
    let inputs = (0..time_slices).map(|_t| {
        (0..3).map(|_dimension| {
            let p1_min = f.garbler_input_bundle_binary(nbits);
            let p1_max = f.garbler_input_bundle_binary(nbits);
            let p2_min = f.evaluator_input_bundle_binary(nbits);
            let p2_max = f.evaluator_input_bundle_binary(nbits);
            (p1_min, p1_max, p2_min, p2_max)
        }).collect_vec()
    }).collect_vec();

    let collisions = (0..time_slices).map(|t| {
        let bits = (0..3).map(|dimension| {
            let (p1_min, p1_max, p2_min, p2_max) = &inputs[t][dimension];
            let bits = [f.exact_geq(&p1_min, &p2_min), f.exact_lt(&p1_max, &p2_max)];
            f.or_many(&bits)
        }).collect_vec();
        f.or_many(&bits)
    }).collect_vec();

    let result = f.or_many(&collisions);
    f.output(&result);
}

fn main() {
    let nbits = 20;
    let time_slices = 200;

    bench(10,
        Box::new(move |f| collision(f, nbits, time_slices)),
        Box::new(move |f| collision(f, nbits, time_slices))
    );
}
