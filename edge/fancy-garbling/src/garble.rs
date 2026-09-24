//! Structs and functions for creating, streaming, and evaluating garbled circuits.

mod evaluator;
mod garbler;

pub use crate::garble::{evaluator::Evaluator, garbler::Garbler};

#[cfg(test)]
mod helpers {
    use rand::rng;

    use fancy_plaintext::{Dummy, DummyVal};
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};
    use swanky_field_binary::F2;

    pub(crate) fn plaintext<C: CircuitInputMapper<Dummy> + CircuitOutputMapper<Dummy>>(
        circuit: &C,
    ) -> (Vec<F2>, Vec<F2>) {
        let mut rng = rng();

        let inputs = (0..<C as CircuitInputMapper<Dummy>>::ninputs(circuit))
            .map(|_| DummyVal::rand(&mut rng))
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

        (plaintext, expected)
    }
}

#[cfg(test)]
mod nonstreaming {
    use crate::{Evaluator, Garbler, WireLabel, WireMod2, classic::GarbledCircuit};
    use fancy_circuits::test_circuits::binary::TestOrGateFanN;
    use fancy_plaintext::Dummy;
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};
    use swanky_field_binary::F2;
    use swanky_rng::SwankyRng;

    // Check that non-streaming evaluation of a circuit execution equals the
    // dummy evaluation of the same function.
    fn garble_test_helper<
        W: WireLabel<F2>,
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
            let (inputs, expected) = super::helpers::plaintext(circuit);

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
    fn or_many() {
        garble_test_helper::<WireMod2, _>(&TestOrGateFanN(16));
    }
}

#[cfg(test)]
mod streaming {
    use crate::{Evaluator, Garbler, WireLabel, WireMod2};
    use fancy_circuits::test_circuits::binary::TestOrGateFanN;
    use fancy_plaintext::Dummy;
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};
    use fancy_traits::{FancyEncode, FancyOutput};
    use swanky_field_binary::F2;
    use swanky_rng::SwankyRng;

    // Check that streaming evaluation of a circuit execution equals the dummy
    // evaluation of the same function.
    fn streaming_test_helper<
        W: WireLabel<F2> + Send,
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

        let (inputs, expected) = super::helpers::plaintext(circuit);

        let mut gb = Garbler::new(rng);
        let mut ev = Evaluator::new();
        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let zeros = gb.encode_many(&inputs, channel)?;
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
                let wires = ev.receive_many(inputs.len(), channel)?;
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
    fn or_many() {
        streaming_test_helper::<WireMod2, _>(&TestOrGateFanN(16));
    }
}
