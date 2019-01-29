#![feature(non_ascii_idents)]
#![feature(test)]

mod comm;
mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[macro_use]
extern crate arrayref;

use fancy_garbling::Wire;

#[inline(always)]
fn wire_to_u8vec(wire: Wire) -> Vec<u8> {
    wire.as_u128().to_le_bytes().to_vec()
}
#[inline(always)]
fn u8vec_to_wire(v: &[u8], modulus: u16) -> Wire {
    let wire = array_ref![v, 0, 16];
    Wire::from_u128(u128::from_le_bytes(*wire), modulus)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use fancy_garbling::{Fancy, HasModulus};
    use ocelot::{DummyOT, ObliviousTransfer};
    use std::os::unix::net::UnixStream;

    const Q: u16 = 3;

    fn circuit<F, W>(f: &mut F)
    where
        W: HasModulus + Clone,
        F: Fancy<Item = W>,
    {
        let a = f.garbler_input(None, Q);
        let b = f.evaluator_input(None, Q);
        let c = f.add(&a, &b);
        f.output(None, &c);
    }

    fn test_simple_circuit<OT: ObliviousTransfer<UnixStream>>(a: u16, b: u16) {
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => panic!("Couldn't create pair of sockets: {:?}", e),
        };
        std::thread::spawn(move || {
            let mut gb = Garbler::<UnixStream, OT>::new(sender, &[a]);
            circuit(&mut gb);
        });
        let mut ev = Evaluator::<UnixStream, OT>::new(receiver, &[b]);
        circuit(&mut ev);
        let output = ev.decode_output();
        assert_eq!(vec![(a + b) % Q], output);
    }

    #[test]
    fn test() {
        test_simple_circuit::<DummyOT<UnixStream>>(0, 0);
        test_simple_circuit::<DummyOT<UnixStream>>(1, 0);
        test_simple_circuit::<DummyOT<UnixStream>>(2, 0);
        test_simple_circuit::<DummyOT<UnixStream>>(0, 1);
        test_simple_circuit::<DummyOT<UnixStream>>(0, 2);
        test_simple_circuit::<DummyOT<UnixStream>>(1, 1);
        test_simple_circuit::<DummyOT<UnixStream>>(2, 1);
        test_simple_circuit::<DummyOT<UnixStream>>(1, 2);
        test_simple_circuit::<DummyOT<UnixStream>>(2, 2);
    }

}
