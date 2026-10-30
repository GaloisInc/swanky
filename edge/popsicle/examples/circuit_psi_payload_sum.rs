use fancy_traits::FancyOutput;
use popsicle::circuit_psi::{
    PAYLOAD_SIZE,
    base_psi::{receiver::OpprfReceiver, sender::OpprfSender},
    circuits::fancy_payload_sum,
    intersect_with_payloads,
    utils::{binary_to_u128, int_vec_block512},
};
use rand::SeedableRng;
use swanky_block::Block512;
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{Receiver, Sender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

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
            let mut gb = Garbler::<_, IKNP<Sender>, _>::new(channel, rng.fork())?;

            let intersection_results = intersect_with_payloads::<_, OpprfSender, _>(
                &mut gb,
                set_a,
                Some(payload_a),
                channel,
                &mut rng,
            )
            .unwrap();
            let res = fancy_payload_sum(
                &mut gb,
                &intersection_results.intersection.existence_bit_vector,
                &intersection_results.payloads.sender_payloads,
                &intersection_results.payloads.receiver_payloads,
                channel,
            )
            .unwrap();
            gb.outputs(res.wires(), channel).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();

            let mut ev = Evaluator::<_, IKNP<Receiver>, _>::new(channel, rng.fork()).unwrap();
            let intersection_results = intersect_with_payloads::<_, OpprfReceiver, _>(
                &mut ev,
                set_b,
                Some(payload_b),
                channel,
                &mut rng,
            )
            .unwrap();
            let res = fancy_payload_sum(
                &mut ev,
                &intersection_results.intersection.existence_bit_vector,
                &intersection_results.payloads.sender_payloads,
                &intersection_results.payloads.receiver_payloads,
                channel,
            )
            .unwrap();
            let res_out = ev
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
