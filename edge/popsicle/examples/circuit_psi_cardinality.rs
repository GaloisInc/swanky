use fancy_traits::{Circuit, FancyOutput};
use popsicle::circuit_psi::{
    base_psi::{receiver::OpprfReceiver, sender::OpprfSender},
    circuits::Cardinality,
    intersect,
    utils::binary_to_u128,
};
use rand::SeedableRng;
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{Receiver, Sender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

const SET_SIZE: usize = 1 << 8;

pub fn psty_cardinality(set_a: &[Vec<u8>], set_b: &[Vec<u8>]) -> u128 {
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let mut gb = Garbler::<_, IKNP<Sender>, _>::new(channel, rng.fork())?;

            let intersection_results =
                intersect::<_, OpprfSender, _>(&mut gb, set_a, channel, &mut rng).unwrap();
            let res = Cardinality::new().execute(
                &mut gb,
                &intersection_results.intersection.existence_bit_vector,
                channel,
            )?;
            gb.outputs(res.wires(), channel).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();
            let mut ev = Evaluator::<_, IKNP<Receiver>, _>::new(channel, rng.fork()).unwrap();
            let intersection_results =
                intersect::<_, OpprfReceiver, _>(&mut ev, set_b, channel, &mut rng).unwrap();
            let res = Cardinality::new()
                .execute(
                    &mut ev,
                    &intersection_results.intersection.existence_bit_vector,
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

    let res = psty_cardinality(&set_a, &set_b);
    println!("Result is {} and should be {}", res, (SET_SIZE - 1));
}
