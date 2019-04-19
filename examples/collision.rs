use itertools::Itertools;

use fancy_garbling::{self, informer::Informer, BinaryGadgets, Fancy, HasModulus};

fn collision<W, F>(f: &mut F, nbits: usize, time_slices: usize, check_for_cheaters: bool)
where
    F: Fancy<Item = W>,
    W: Clone + HasModulus,
{
    // obtain inputs into a vec of vecs of arrays of 4
    let inputs = (0..time_slices)
        .map(|_t| {
            (0..3)
                .map(|_dimension| {
                    let p1_min = f.bin_garbler_input_bundle(nbits, None).unwrap();
                    let p1_max = f.bin_garbler_input_bundle(nbits, None).unwrap();
                    let p2_min = f.bin_evaluator_input_bundle(nbits).unwrap();
                    let p2_max = f.bin_evaluator_input_bundle(nbits).unwrap();
                    [p1_min, p1_max, p2_min, p2_max]
                })
                .collect_vec()
        })
        .collect_vec();

    // check for collisions
    let collisions = (0..time_slices)
        .flat_map(|t| {
            (0..3)
                .map(|d| {
                    // d=dimension
                    let [p1_min, p1_max, p2_min, p2_max] = &inputs[t][d];
                    // p1_min > p2_min && p1_min < p2_max
                    let left = f.bin_geq(p1_min, p2_min).unwrap();
                    let right = f.bin_lt(p1_min, p2_max).unwrap();
                    let case1 = f.and(&left, &right).unwrap();

                    // p1_max > p2_min && p1_max < p2_max
                    let left = f.bin_geq(p1_max, p2_min).unwrap();
                    let right = f.bin_lt(p1_max, p2_max).unwrap();
                    let case2 = f.and(&left, &right).unwrap();

                    // p1_min < p2_min && p1_max > p2_max
                    let left = f.bin_lt(p1_min, p2_min).unwrap();
                    let right = f.bin_geq(p1_max, p2_max).unwrap();
                    let case3 = f.and(&left, &right).unwrap();

                    f.or_many(&[case1, case2, case3]).unwrap()
                })
                .collect_vec()
        })
        .collect_vec();

    let collision = f.or_many(&collisions).unwrap();

    if check_for_cheaters {
        // we want to ensure that the difference of two inputs of any two sequential time
        // slices are at most delta.
        let delta = f.bin_constant_bundle(10, nbits).unwrap();

        let possible_cheats = (1..time_slices)
            .flat_map(|t| {
                (0..3)
                    .flat_map(|d| {
                        (0..4)
                            .map(|i| {
                                // ensure the difference between t and the previous t is at most delta
                                let (diff, _) = f
                                    .bin_subtraction(&inputs[t][d][i], &inputs[t - 1][d][i])
                                    .unwrap();
                                let abs = f.bin_abs(&diff).unwrap();
                                f.bin_geq(&abs, &delta).unwrap()
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        let cheater_detected = f.or_many(&possible_cheats).unwrap();
        let output = f.or(&collision, &cheater_detected).unwrap();

        f.output(&output).unwrap();
    } else {
        f.output(&collision).unwrap();
    }
}

fn main() {
    let nbits = 32;
    let time_slices = 1800;
    let check_for_cheaters = false;

    let mut informer = Informer::new();
    collision(&mut informer, nbits, time_slices, check_for_cheaters);
    informer.print_info();
    println!("");
}
