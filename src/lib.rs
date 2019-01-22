#![feature(test)]

mod comm;
pub mod evaluator;
pub mod garbler;

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use fancy_garbling::fancy::{Fancy, HasModulus};
    use ocelot::ot::chou_orlandi::ChouOrlandiOT;
    use ocelot::ot::dummy::DummyOT;
    use ocelot::ot::iknp::IknpOT;
    use ocelot::ot::naor_pinkas::NaorPinkasOT;
    use ocelot::ot::ObliviousTransfer;
    use std::os::unix::net::UnixStream;

    fn circuit<F, W>(f: &mut F)
    where
        W: HasModulus + Default + Clone,
        F: Fancy<Item = W>,
    {
        let q = 17;
        let a = f.garbler_input(None, q);
        let b = f.evaluator_input(None, q);
        let c = f.add(&a, &b);
        f.output(None, &c);
    }

    fn test_simple_circuit<OT: ObliviousTransfer<UnixStream>>(a: bool, b: bool) {
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        std::thread::spawn(move || {
            let mut gb = garbler::garble::<UnixStream, OT>(sender, &[a as u16]).unwrap();
            circuit(&mut gb);
        });
        let mut ev = evaluator::evaluate::<UnixStream, OT>(receiver, &[b as u16]).unwrap();
        circuit(&mut ev);
        let output = ev.decode_output();
        let result = a as u16 + b as u16;
        assert_eq!(vec![result], output);
    }

    #[test]
    fn test_dummy() {
        test_simple_circuit::<DummyOT<UnixStream>>(false, false);
        test_simple_circuit::<DummyOT<UnixStream>>(false, true);
        test_simple_circuit::<DummyOT<UnixStream>>(true, false);
        test_simple_circuit::<DummyOT<UnixStream>>(true, true);
    }

    #[test]
    fn test_chou_orlandi() {
        test_simple_circuit::<ChouOrlandiOT<UnixStream>>(false, false);
        test_simple_circuit::<ChouOrlandiOT<UnixStream>>(false, true);
        test_simple_circuit::<ChouOrlandiOT<UnixStream>>(true, false);
        test_simple_circuit::<ChouOrlandiOT<UnixStream>>(true, true);
    }

    #[test]
    fn test_naor_pinkas() {
        test_simple_circuit::<NaorPinkasOT<UnixStream>>(false, false);
        test_simple_circuit::<NaorPinkasOT<UnixStream>>(false, true);
        test_simple_circuit::<NaorPinkasOT<UnixStream>>(true, false);
        test_simple_circuit::<NaorPinkasOT<UnixStream>>(true, true);
    }

    #[test]
    fn test_iknp() {
        test_simple_circuit::<IknpOT<UnixStream, DummyOT<UnixStream>>>(false, false);
        test_simple_circuit::<IknpOT<UnixStream, DummyOT<UnixStream>>>(false, true);
        test_simple_circuit::<IknpOT<UnixStream, DummyOT<UnixStream>>>(true, false);
        test_simple_circuit::<IknpOT<UnixStream, DummyOT<UnixStream>>>(true, true);
    }

}
