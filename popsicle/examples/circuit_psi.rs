use popsicle::{
    circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender},
        tests::utils::{type_aliases::*, *},
        utils::binary_to_u128,
        *,
        {evaluator::PsiEvaluator, garbler::PsiGarbler, CircuitPsi},
    },
    errors::Error,
};

use fancy_garbling::{AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyBinary, FancyReveal};
use rand::Rng;
use scuttlebutt::{AesRng, Block, Block512};
use std::{fmt::Debug, os::unix::net::UnixStream, thread};
const SET_SIZE: usize = 1 << 8;

pub fn fancy_silly_example<F, E>() -> impl FnMut(
    &mut F,
    &[<F as Fancy>::Item],
    &[BinaryBundle<<F as Fancy>::Item>],
    Option<Vec<BinaryBundle<<F as Fancy>::Item>>>,
    Option<Vec<BinaryBundle<<F as Fancy>::Item>>>,
) -> Result<BinaryBundle<<F as Fancy>::Item>, Error>
where
    F: FancyBinary + FancyReveal + Fancy<Item = AllWire, Error = E>,
    E: Debug,
    Error: From<E>,
{
    |f, intersect_bitvec, set, payload_a, payload_b| {
        let mut acc = f.bin_constant_bundle(0, PAYLOAD_SIZE * 8)?;
        let zero = f.bin_constant_bundle(0, PAYLOAD_SIZE * 8)?;

        for (i, bit) in intersect_bitvec.iter().enumerate() {
            let mux_a = f.bin_multiplex(bit, &zero, &payload_a.as_ref().unwrap()[i])?;
            let mux_b = f.bin_multiplex(bit, &zero, &payload_b.as_ref().unwrap()[i])?;
            let mul = f.bin_addition_no_carry(&mux_a, &mux_b)?;
            acc = f.bin_addition_no_carry(&acc, &mul)?;
            acc = f.bin_addition_no_carry(&acc, &set[i])?;
        }
        Ok(acc)
    }
}

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
            let mut channel = setup(sender);
            let mut gb = PsiGarbler::new(&mut channel, rng.gen::<Block>()).unwrap();

            let res = gb
                .circuit_psi_psty::<OpprfSender, _, _>(
                    set_a,
                    Some(payload_a),
                    &mut fancy_silly_example::<Gb, _>(),
                )
                .unwrap();
            gb.gb.outputs(res.wires()).unwrap();
        });
        let mut rng = AesRng::new();
        let mut channel = setup(receiver);
        let mut ev = PsiEvaluator::new(&mut channel, rng.gen::<Block>()).unwrap();

        let res = ev
            .circuit_psi_psty::<OpprfReceiver, _, _>(
                set_b,
                Some(payload_b),
                &mut fancy_silly_example::<Ev, _>(),
            )
            .unwrap();
        let res_out = ev
            .ev
            .outputs(res.wires())
            .unwrap()
            .expect("evaluator should produce outputs");
        binary_to_u128(res_out)
    })
}

pub fn main() {
    let set_a: Vec<Vec<u8>> = (0..100u64).map(|el| el.to_le_bytes().to_vec()).collect();
    let mut set_b = set_a.clone();
    set_b[10] = (SET_SIZE + 1).to_le_bytes().to_vec();

    let payload_a = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
    let payload_b = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);

    let res = psty_payload_sum(&set_a, &set_b, &payload_a, &payload_b);
    println!("Result is {} and should be {}", res, (SET_SIZE - 1) * 2);
}
