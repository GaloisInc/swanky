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
use scuttlebutt::{AesRng, Block};
use std::{fmt::Debug, os::unix::net::UnixStream, thread};
const SET_SIZE: usize = 1 << 8;

pub fn fancy_cardinality<F, E>() -> impl FnMut(
    &mut F,
    &[<F as Fancy>::Item],
    &[BinaryBundle<<F as Fancy>::Item>],
) -> Result<BinaryBundle<<F as Fancy>::Item>, Error>
where
    F: FancyBinary + FancyReveal + Fancy<Item = AllWire, Error = E>,
    E: Debug,
    Error: From<E>,
{
    |f, intersect_bitvec, _| {
        let mut acc = f.bin_constant_bundle(0, ELEMENT_SIZE * 8)?;
        let one = f.bin_constant_bundle(1, ELEMENT_SIZE * 8)?;
        let zero = f.bin_constant_bundle(0, ELEMENT_SIZE * 8)?;
        for bit in intersect_bitvec {
            let mux = f.bin_multiplex(bit, &zero, &one)?;
            acc = f.bin_addition_no_carry(&acc, &mux)?;
        }
        Ok(acc)
    }
}

pub fn psty_cardinality(set_a: &[Vec<u8>], set_b: &[Vec<u8>]) -> u128 {
    let (sender, receiver) = UnixStream::pair().unwrap();
    thread::scope(|s| {
        let _ = s.spawn(|| {
            let mut rng = AesRng::new();
            let mut channel = setup(sender);
            let mut gb = PsiGarbler::new(&mut channel, rng.gen::<Block>()).unwrap();

            let res = gb
                .circuit_psi_psty_no_payloads::<OpprfSender, _, _>(
                    set_a,
                    &mut fancy_cardinality::<Gb, _>(),
                )
                .unwrap();
            gb.gb.outputs(res.wires()).unwrap();
        });
        let mut rng = AesRng::new();
        let mut channel = setup(receiver);
        let mut ev = PsiEvaluator::new(&mut channel, rng.gen::<Block>()).unwrap();

        let res = ev
            .circuit_psi_psty_no_payloads::<OpprfReceiver, _, _>(
                set_b,
                &mut fancy_cardinality::<Ev, _>(),
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
    let set_a: Vec<Vec<u8>> = (0..SET_SIZE).map(|el| el.to_le_bytes().to_vec()).collect();
    let mut set_b = set_a.clone();
    set_b[10] = (SET_SIZE + 1).to_le_bytes().to_vec();

    let res = psty_cardinality(&set_a, &set_b);
    println!("Result is {} and should be {}", res, (SET_SIZE - 1));
}
