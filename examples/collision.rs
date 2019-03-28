use itertools::Itertools;

use fancy_garbling::{self, informer::Informer, BundleGadgets, Fancy, HasModulus};

fn collision<W, F>(f: &F, nbits: usize, time_slices: usize, check_for_cheaters: bool)
where
    F: Fancy<Item = W>,
    W: Clone + HasModulus,
{
    // obtain inputs into a vec of vecs of arrays of 4
    let inputs = (0..time_slices)
        .map(|_t| {
            (0..3)
                .map(|_dimension| {
                    let p1_min = f.garbler_input_bundle_binary(nbits, None).unwrap();
                    let p1_max = f.garbler_input_bundle_binary(nbits, None).unwrap();
                    let p2_min = f.evaluator_input_bundle_binary(nbits).unwrap();
                    let p2_max = f.evaluator_input_bundle_binary(nbits).unwrap();
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
                    let left = f.geq(p1_min, p2_min, "100%").unwrap();
                    let right = f.lt(p1_min, p2_max, "100%").unwrap();
                    let case1 = f.and(&left, &right).unwrap();

                    // p1_max > p2_min && p1_max < p2_max
                    let left = f.geq(p1_max, p2_min, "100%").unwrap();
                    let right = f.lt(p1_max, p2_max, "100%").unwrap();
                    let case2 = f.and(&left, &right).unwrap();

                    // p1_min < p2_min && p1_max > p2_max
                    let left = f.lt(p1_min, p2_min, "100%").unwrap();
                    let right = f.geq(p1_max, p2_max, "100%").unwrap();
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
        let delta = f.constant_bundle_binary(10, nbits).unwrap();

        let possible_cheats = (1..time_slices)
            .flat_map(|t| {
                (0..3)
                    .flat_map(|d| {
                        (0..4)
                            .map(|i| {
                                // ensure the difference between t and the previous t is at most delta
                                let (diff, _) = f
                                    .binary_subtraction(&inputs[t][d][i], &inputs[t - 1][d][i])
                                    .unwrap();
                                let abs = f.abs(&diff).unwrap();
                                f.geq(&abs, &delta, "100%").unwrap()
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

    let informer = Informer::new();
    collision(&informer, nbits, time_slices, check_for_cheaters);
    informer.print_info();
    println!("");
}
