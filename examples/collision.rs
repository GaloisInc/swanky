use fancy_garbling::fancy::{Fancy, BundleGadgets, HasModulus};
use fancy_garbling::garble::bench_garbling;
use fancy_garbling::informer::Informer;
use itertools::Itertools;
use fancy_garbling::util;

fn collision<W,F>(f: &F, nbits: usize, time_slices: usize, check_for_cheaters: bool)
    where F: Fancy<Item=W>, W: Clone + Default + HasModulus
{
    // obtain inputs into a vec of vecs of arrays of 4
    let inputs = (0..time_slices).map(|_t| {
        (0..3).map(|_dimension| {
            let p1_min = f.garbler_input_bundle_binary(None, nbits);
            let p1_max = f.garbler_input_bundle_binary(None, nbits);
            let p2_min = f.evaluator_input_bundle_binary(None, nbits);
            let p2_max = f.evaluator_input_bundle_binary(None, nbits);
            [p1_min, p1_max, p2_min, p2_max]
        }).collect_vec()
    }).collect_vec();

    // check for collisions
    let collisions = (0..time_slices).flat_map(|t| {
        (0..3).map(|d| { // d=dimension
            let [p1_min, p1_max, p2_min, p2_max] = &inputs[t][d];
            // p1_min > p2_min && p1_min < p2_max
            let left  = f.exact_geq(None, p1_min, p2_min);
            let right = f.exact_lt(None, p1_min, p2_max);
            let case1 = f.and(None, &left, &right);

            // p1_max > p2_min && p1_max < p2_max
            let left  = f.exact_geq(None, p1_max, p2_min);
            let right = f.exact_lt(None, p1_max, p2_max);
            let case2 = f.and(None, &left, &right);

            // p1_min < p2_min && p1_max > p2_max
            let left  = f.exact_lt(None, p1_min, p2_min);
            let right = f.exact_geq(None, p1_max, p2_max);
            let case3 = f.and(None, &left, &right);

            f.or_many(None, &[case1, case2, case3])
        }).collect_vec()
    }).collect_vec();

    let collision = f.or_many(None, &collisions);

    if check_for_cheaters {
        // we want to ensure that the difference of two inputs of any two sequential time
        // slices are at most delta.
        let delta = f.constant_bundle_binary(None, &util::u128_to_bits(10, nbits));

        let possible_cheats = (1..time_slices).flat_map(|t| {
            (0..3).flat_map(|d| {
                (0..4).map(|i| {
                    // ensure the difference between t and the previous t is at most delta
                    let (diff, _) = f.binary_subtraction(None, &inputs[t][d][i], &inputs[t-1][d][i]);
                    let abs  = f.abs(None, &diff);
                    f.exact_geq(None, &abs, &delta)
                }).collect_vec()
            }).collect_vec()
        }).collect_vec();

        let cheater_detected = f.or_many(None, &possible_cheats);
        let output = f.or(None, &collision, &cheater_detected);

        f.output(None, &output);
    } else {
        f.output(None, &collision);
    }
}

fn main() {
    let nbits = 32;
    let time_slices = 1800;
    let check_for_cheaters = false;

    let informer = Informer::new();
    collision(&informer, nbits, time_slices, check_for_cheaters);
    informer.print_info();
    println!("");

    bench_garbling(10,
        move |f| collision(f, nbits, time_slices, check_for_cheaters),
        move |f| collision(f, nbits, time_slices, check_for_cheaters)
    );
}
