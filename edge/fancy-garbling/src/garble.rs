//! Structs and functions for creating, streaming, and evaluating garbled circuits.

mod evaluator;
mod garbler;
mod security_warning;

pub use crate::garble::{evaluator::Evaluator, garbler::Garbler};

#[cfg(test)]
mod helpers {
    use rand::{RngExt, rng};

    use fancy_plaintext::{Dummy, DummyVal};
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};

    pub(crate) fn plaintext<C: CircuitInputMapper<Dummy> + CircuitOutputMapper<Dummy>>(
        circuit: &C,
    ) -> (Vec<u16>, Vec<u16>, Vec<u16>) {
        let mut rng = rng();

        let moduli = (0..<C as CircuitInputMapper<Dummy>>::ninputs(circuit))
            .map(|i| <C as CircuitInputMapper<Dummy>>::modulus(circuit, i))
            .collect::<Vec<_>>();
        let inputs = moduli
            .iter()
            .map(|q| {
                let x = rng.random::<u16>() % q;
                DummyVal::new(x, *q)
            })
            .collect::<Vec<_>>();
        let plaintext = inputs.iter().map(|x| x.val()).collect::<Vec<_>>();

        let expected = Dummy::eval(
            circuit,
            <C as CircuitInputMapper<Dummy>>::map(circuit, inputs),
        )
        .unwrap();
        let expected = C::flatten(expected)
            .iter()
            .map(|x| x.val())
            .collect::<Vec<_>>();

        (plaintext, moduli, expected)
    }
}

#[cfg(test)]
mod nonstreaming {
    use crate::{AllWire, Evaluator, Garbler, WireLabel, WireMod2, classic::GarbledCircuit};
    use fancy_circuits::test_circuits::{
        arithmetic::{
            TestAddMany, TestAddition, TestCmul, TestConstants, TestMulGate,
            TestMulGateUnequalMods, TestSubtraction,
        },
        binary::TestOrGateFanN,
        proj::{TestProj, TestProjRand},
    };
    use fancy_circuits::util::RngExt;
    use fancy_plaintext::Dummy;
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};
    use rand::{RngExt as _, rng};
    use swanky_rng::SwankyRng;

    // Check that non-streaming evaluation of a circuit execution equals the
    // dummy evaluation of the same function.
    fn garble_test_helper<
        W: WireLabel,
        Ex: CircuitInputMapper<Dummy>
            + CircuitOutputMapper<Dummy>
            + CircuitInputMapper<Garbler<SwankyRng, W>>
            + CircuitOutputMapper<Garbler<SwankyRng, W>>
            + CircuitInputMapper<Evaluator<W>>
            + CircuitOutputMapper<Evaluator<W>>,
    >(
        circuit: &Ex,
    ) {
        for _ in 0..16 {
            let (inputs, _, expected) = super::helpers::plaintext(circuit);

            let (en, ev, output_mapping) =
                GarbledCircuit::garble::<W, _, _>(circuit, SwankyRng::new()).unwrap();

            let xs = en.encode_inputs(&inputs);
            let wirelabels = ev
                .eval_to_wirelabels(
                    circuit,
                    <Ex as CircuitInputMapper<Evaluator<W>>>::map(circuit, xs),
                )
                .unwrap();
            let decoded = output_mapping
                .to_outputs(&<Ex as CircuitOutputMapper<Evaluator<W>>>::flatten(
                    wirelabels,
                ))
                .unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn add() {
        let q = rng().gen_prime();
        garble_test_helper::<AllWire, _>(&TestAddition(q));
    }

    #[test]
    fn add_many() {
        let q = rng().gen_prime();
        garble_test_helper::<AllWire, _>(&TestAddMany(q, 16));
    }

    #[test]
    fn or_many() {
        garble_test_helper::<WireMod2, _>(&TestOrGateFanN(16));
    }

    #[test]
    fn sub() {
        let q = rng().gen_prime();
        garble_test_helper::<AllWire, _>(&TestSubtraction(q));
    }

    #[test]
    fn cmul() {
        let q = rng().gen_prime();
        let c = rng().random::<u16>() % q;
        garble_test_helper::<AllWire, _>(&TestCmul(q, c));
    }

    #[test]
    fn proj() {
        let q = rng().gen_prime();
        garble_test_helper::<AllWire, _>(&TestProj(q));
    }

    #[test]
    fn proj_rand() {
        let q = rng().gen_prime();
        let tab = (0..q)
            .map(|_| rng().random::<u16>() % q)
            .collect::<Vec<_>>();

        garble_test_helper::<AllWire, _>(&TestProjRand(q, tab));
    }

    #[test]
    fn arithmetic_half_gate() {
        let q = rng().gen_prime();
        garble_test_helper::<AllWire, _>(&TestMulGate(q));
    }

    #[test]
    fn half_gate_unequal_mods() {
        let q = rng().gen_prime();
        // Lower modulus is capped at 8.
        let p = 2 + rng().gen_prime() % 6;
        garble_test_helper::<AllWire, _>(&TestMulGateUnequalMods([q, p]));
    }

    #[test]
    fn constants() {
        let q = rng().gen_modulus();
        let c = rng().random::<u16>() % q;
        garble_test_helper::<AllWire, _>(&TestConstants(q, c));
    }
}

#[cfg(test)]
mod streaming {
    use crate::{AllWire, Evaluator, Garbler, WireLabel};
    use fancy_circuits::arithmetic::{Constant, Multiplication, ReLU};
    use fancy_circuits::test_circuits::arithmetic::{
        TestAddition, TestCmul, TestMulGate, TestSubtraction,
    };
    use fancy_circuits::test_circuits::proj::TestProj;
    use fancy_circuits::util::RngExt;
    use fancy_circuits::{CrtBundle, CrtGadgets};
    use fancy_plaintext::Dummy;
    use fancy_traits::{
        Circuit, CircuitInputMapper, CircuitOutputMapper, FancyConstant, HasModulus,
    };
    use fancy_traits::{FancyArithmetic, FancyEncode, FancyOutput, FancyProj};
    use rand::{RngExt as _, rng};
    use swanky_channel::Channel;
    use swanky_error::Result;
    use swanky_rng::SwankyRng;

    // Check that streaming evaluation of a circuit execution equals the dummy
    // evaluation of the same function.
    fn streaming_test_helper<
        W: WireLabel + Send,
        Ex: CircuitInputMapper<Dummy>
            + CircuitOutputMapper<Dummy>
            + CircuitInputMapper<Garbler<SwankyRng, W>>
            + CircuitOutputMapper<Garbler<SwankyRng, W>>
            + CircuitInputMapper<Evaluator<W>>
            + CircuitOutputMapper<Evaluator<W>>
            + Send
            + Sync,
    >(
        circuit: &Ex,
    ) {
        let rng = SwankyRng::new();

        let (inputs, moduli, expected) = super::helpers::plaintext(circuit);

        let mut gb = Garbler::new(rng);
        let mut ev = Evaluator::new();
        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let zeros = gb.encode_many(&inputs, &moduli, channel)?;
                let outputs = circuit.execute(
                    &mut gb,
                    <Ex as CircuitInputMapper<Garbler<_, _>>>::map(circuit, zeros),
                    channel,
                )?;
                gb.outputs(
                    &<Ex as CircuitOutputMapper<Garbler<_, _>>>::flatten(outputs),
                    channel,
                )?;
                Ok(())
            },
            |channel| {
                let wires = ev.receive_many(&moduli, channel)?;
                let outputs = circuit.execute(
                    &mut ev,
                    <Ex as CircuitInputMapper<Evaluator<_>>>::map(circuit, wires),
                    channel,
                )?;
                Ok(ev
                    .outputs(
                        &<Ex as CircuitOutputMapper<Evaluator<_>>>::flatten(outputs),
                        channel,
                    )?
                    .unwrap())
            },
        )
        .unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn addition() {
        let mut rng = rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&TestAddition(q));
        }
    }

    #[test]
    fn subtraction() {
        let mut rng = rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&TestSubtraction(q));
        }
    }

    #[test]
    fn multiplication() {
        let mut rng = rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&TestMulGate(q));
        }
    }

    #[test]
    fn cmul() {
        let mut rng = rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let c = rng.random::<u16>() % q;
            streaming_test_helper::<AllWire, _>(&TestCmul(q, c));
        }
    }

    #[test]
    fn proj() {
        let mut rng = rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&TestProj(q));
        }
    }

    /// Circuit for testing multiple CRT operations.
    struct TestComplexGadget(pub Vec<u16>, pub usize);
    impl<F: FancyArithmetic + FancyConstant + FancyProj + CrtGadgets> Circuit<F> for TestComplexGadget
    where
        F::Item: HasModulus,
    {
        type Input = Vec<CrtBundle<F::Item>>;
        type Output = Vec<CrtBundle<F::Item>>;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let mut outputs = Vec::with_capacity(inputs.len());
            for x in inputs.iter() {
                let c = Constant::new(1, x.composite_modulus()).execute(backend, (), channel)?;
                let y = Multiplication::new().execute(backend, (x, &c), channel)?;
                let accuracy = "100%";
                let none_option: Option<&[u16]> = None;
                let z = ReLU::new().execute(backend, (&y, accuracy, none_option), channel)?;
                outputs.push(z);
            }
            Ok(outputs)
        }
    }
    impl<F: FancyArithmetic + FancyConstant + FancyProj + CrtGadgets> CircuitInputMapper<F>
        for TestComplexGadget
    where
        F::Item: HasModulus,
    {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0.len() * self.1);
            inputs
                .chunks_exact(self.0.len())
                .map(|x| CrtBundle::new(x.to_vec()))
                .collect()
        }

        fn ninputs(&self) -> usize {
            self.0.len() * self.1
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }
    impl<F: FancyArithmetic + FancyConstant + FancyProj + CrtGadgets> CircuitOutputMapper<F>
        for TestComplexGadget
    where
        F::Item: HasModulus,
    {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            output
                .iter()
                .flat_map(|bundle| bundle.wires().to_vec())
                .collect()
        }
    }

    #[test]
    fn complex_gadget() {
        let N = 10;
        let qs = fancy_circuits::util::primes_with_width(10);
        for _ in 0..16 {
            streaming_test_helper::<AllWire, _>(&TestComplexGadget(qs.clone(), N));
        }
    }
}
