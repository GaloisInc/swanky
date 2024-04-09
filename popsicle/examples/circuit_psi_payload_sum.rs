use popsicle::circuit_psi::{
    base_psi::{receiver::OpprfReceiver, sender::OpprfSender},
    circuits::*,
    utils::*,
    *,
    {evaluator::PsiEvaluator, garbler::PsiGarbler, CircuitPsi},
};

use fancy_garbling::Fancy;
use rand::Rng;
use scuttlebutt::{AesRng, Block, Block512};
use std::{os::unix::net::UnixStream, thread};
const SET_SIZE: usize = 1 << 8;

pub fn psty_payload_sum(
    set_a: &[Vec<u8>],
    set_b: &[Vec<u8>],
    payload_a: &[Block512],
    payload_b: &[Block512],
) -> u128 {
    let (sender, receiver) = UnixStream::pair().unwrap();
    thread::scope(|s| {
        let _ = s.spawn(|| {
            let mut rng = AesRng::new();
            let mut channel = setup_channel(sender);
            let mut gb_psi =
                PsiGarbler::<_, AesRng>::new(&mut channel, Block::from(rng.gen::<u128>())).unwrap();

            gb_psi.intersect::<OpprfSender>(set_a, payload_a).unwrap();
            let res = fancy_payload_sum(
                &mut gb_psi.gb,
                &gb_psi.intersection.existence_bit_vector,
                &gb_psi.payloads.sender_payloads,
                &gb_psi.payloads.receiver_payloads,
            )
            .unwrap();
            gb_psi.gb.outputs(res.wires()).unwrap();
        });
        let mut rng = AesRng::new();
        let mut channel = setup_channel(receiver);

        let mut ev_psi =
            PsiEvaluator::<_, AesRng>::new(&mut channel, Block::from(rng.gen::<u128>())).unwrap();
        ev_psi.intersect::<OpprfReceiver>(set_b, payload_b).unwrap();
        let res = fancy_payload_sum(
            &mut ev_psi.ev,
            &ev_psi.intersection.existence_bit_vector,
            &ev_psi.payloads.sender_payloads,
            &ev_psi.payloads.receiver_payloads,
        )
        .unwrap();
        let res_out = ev_psi
            .ev
            .outputs(res.wires())
            .unwrap()
            .expect("evaluator should produce outputs");
        binary_to_u128(res_out)
    })
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
