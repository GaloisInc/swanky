use fancy_traits::FancyOutput;
use popsicle::circuit_psi::{
    CircuitPsi, circuits::*, evaluator::OpprfPsiEvaluator, garbler::OpprfPsiGarbler, utils::*,
};
use swanky_rng::SwankyRng;

const SET_SIZE: usize = 1 << 8;

pub fn psty_cardinality(set_a: &[Vec<u8>], set_b: &[Vec<u8>]) -> u128 {
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let mut gb_psi = OpprfPsiGarbler::new(channel, &mut rng).unwrap();

            let intersection_results = gb_psi.intersect(set_a, channel).unwrap();
            let res = fancy_cardinality(
                &mut gb_psi.gb,
                &intersection_results.intersection.existence_bit_vector,
                channel,
            )
            .unwrap();
            gb_psi.gb.outputs(res.wires(), channel).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();
            let mut ev_psi = OpprfPsiEvaluator::new(channel, &mut rng).unwrap();
            let intersection_results = ev_psi.intersect(set_b, channel).unwrap();
            let res = fancy_cardinality(
                &mut ev_psi.ev,
                &intersection_results.intersection.existence_bit_vector,
                channel,
            )
            .unwrap();
            let res_out = ev_psi
                .ev
                .outputs(res.wires(), channel)
                .unwrap()
                .expect("evaluator should produce outputs");
            Ok(binary_to_u128(res_out))
        },
    )
    .unwrap();
    result
}
pub fn main() {
    let set_a: Vec<Vec<u8>> = (0..SET_SIZE).map(|el| el.to_le_bytes().to_vec()).collect();
    let mut set_b = set_a.clone();
    set_b[10] = (SET_SIZE + 1).to_le_bytes().to_vec();

    let res = psty_cardinality(&set_a, &set_b);
    println!("Result is {} and should be {}", res, (SET_SIZE - 1));
}
