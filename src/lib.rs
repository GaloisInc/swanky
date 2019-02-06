#![feature(non_ascii_idents)]
#![feature(test)]

mod comm;
mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

use fancy_garbling::Wire;
use ocelot::Block;

#[inline(always)]
fn wire_to_block(w: Wire) -> Block {
    w.as_u128().to_le_bytes()
}
#[inline(always)]
fn block_to_wire(b: Block, q: u16) -> Wire {
    Wire::from_u128(u128::from_le_bytes(b), q)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use fancy_garbling::{Fancy, HasModulus};
    use ocelot::{BlockObliviousTransfer, ChouOrlandiOT};
    use std::os::unix::net::UnixStream;

    fn c1<F: Fancy<Item = W>, W: HasModulus + Clone>(f: &mut F) {
        let a = f.garbler_input(None, 3);
        let b = f.evaluator_input(None, 3);
        let c = f.add(&a, &b);
        f.output(None, &c);
    }

    fn test_c1<OT: BlockObliviousTransfer<UnixStream>>(a: u16, b: u16) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut gb = Garbler::<UnixStream, OT>::new(sender, &[a]);
            c1(&mut gb);
        });
        let mut ev = Evaluator::<UnixStream, OT>::new(receiver, &[b]);
        c1(&mut ev);
        let output = ev.decode_output();
        assert_eq!(vec![(a + b) % 3], output);
    }

    fn c2<F: Fancy<Item = W>, W: HasModulus + Clone>(f: &mut F) {
        let a = f.garbler_input(None, 7);
        let bs = f.evaluator_inputs(None, &[7, 7, 7]);
        let c = f.add_many(&bs);
        let d = f.add(&a, &c);
        f.output(None, &d);
    }

    fn test_c2<OT: BlockObliviousTransfer<UnixStream>>(a: u16, bs: &[u16]) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut gb = Garbler::<UnixStream, OT>::new(sender, &[a]);
            c2(&mut gb);
        });
        let mut ev = Evaluator::<UnixStream, OT>::new(receiver, bs);
        c2(&mut ev);
        let output = ev.decode_output();
        let sum = bs.into_iter().fold(a, |sum, v| sum + v);
        assert_eq!(vec![sum % 7], output);
    }

    #[test]
    fn test() {
        test_c1::<ChouOrlandiOT<UnixStream>>(0, 0);
        test_c1::<ChouOrlandiOT<UnixStream>>(1, 0);
        test_c1::<ChouOrlandiOT<UnixStream>>(2, 0);
        test_c1::<ChouOrlandiOT<UnixStream>>(0, 1);
        test_c1::<ChouOrlandiOT<UnixStream>>(0, 2);
        test_c1::<ChouOrlandiOT<UnixStream>>(1, 1);
        test_c1::<ChouOrlandiOT<UnixStream>>(2, 1);
        test_c1::<ChouOrlandiOT<UnixStream>>(1, 2);
        test_c1::<ChouOrlandiOT<UnixStream>>(2, 2);

        test_c2::<ChouOrlandiOT<UnixStream>>(1, &[1, 1, 1]);
        test_c2::<ChouOrlandiOT<UnixStream>>(4, &[1, 2, 3]);
    }

}
