use fancy_traits::FancyOutput;
use popsicle::circuit_psi::{
    CircuitPsi, PAYLOAD_SIZE, circuits::*, evaluator::OpprfPsiEvaluator, garbler::OpprfPsiGarbler,
    utils::*,
};
use swanky_block::Block512;
use swanky_rng::SwankyRng;

const SET_SIZE: usize = 1 << 8;

pub fn psty_payload_sum(
    set_a: &[Vec<u8>],
    set_b: &[Vec<u8>],
    payload_a: &[Block512],
    payload_b: &[Block512],
) -> u128 {
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let mut gb_psi = OpprfPsiGarbler::new(channel, &mut rng).unwrap();

            let intersection_results = gb_psi
                .intersect_with_payloads(set_a, Some(payload_a), channel)
                .unwrap();
            let res = fancy_payload_sum(
                &mut gb_psi.gb,
                &intersection_results.intersection.existence_bit_vector,
                &intersection_results.payloads.sender_payloads,
                &intersection_results.payloads.receiver_payloads,
                channel,
            )
            .unwrap();
            gb_psi.gb.outputs(res.wires(), channel).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();

            let mut ev_psi = OpprfPsiEvaluator::<SwankyRng>::new(channel, &mut rng).unwrap();
            let intersection_results = ev_psi
                .intersect_with_payloads(set_b, Some(payload_b), channel)
                .unwrap();
            let res = fancy_payload_sum(
                &mut ev_psi.ev,
                &intersection_results.intersection.existence_bit_vector,
                &intersection_results.payloads.sender_payloads,
                &intersection_results.payloads.receiver_payloads,
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

    let payload_a = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
    let payload_b = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);

    let res = psty_payload_sum(&set_a, &set_b, &payload_a, &payload_b);
    println!("Result is {} and should be {}", res, (SET_SIZE - 1) * 2);
}
