//! Implementation of semi-honest two-party computation.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_analyzer::CircuitAnalyzer;
    use fancy_circuits::{crypto::aes::Aes128, test_circuits::binary::TestAndGate};
    use fancy_garbling::{WireLabel, WireMod2};
    use fancy_plaintext::{Dummy, DummyVal};
    use fancy_traits::{
        Circuit, CircuitInputMapper, CircuitOutputMapper, FancyEncode, FancyOutput,
    };
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_ot_chou_orlandi_new::ChouOrlandi;
    use swanky_ot_traits_new::{Receiver, Sender};
    use swanky_rng::SwankyRng;

    #[test]
    fn test_and_gate() {
        let circuit = TestAndGate;
        for a in [F2::ZERO, F2::ONE] {
            for b in [F2::ZERO, F2::ONE] {
                let (_, output) = swanky_channel::local::local_channel_pair(
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut gb =
                            Garbler::<SwankyRng, ChouOrlandi<Sender>, _>::new(channel, rng)?;
                        let x = gb.encode(a, channel)?;
                        let y = gb.receive(channel)?;
                        let outputs = circuit.execute(&mut gb, (x, y), channel)?;
                        let result = gb.output(&outputs, channel)?;
                        assert!(result.is_none());
                        Ok(())
                    },
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut ev =
                            Evaluator::<SwankyRng, ChouOrlandi<Receiver>, _>::new(channel, rng)?;
                        let x = ev.receive(channel)?;
                        let y = ev.encode(b, channel)?;
                        let output = circuit.execute(&mut ev, (x, y), channel)?;
                        let result = ev.output(&output, channel)?;
                        Ok(result.unwrap())
                    },
                )
                .unwrap();
                assert_eq!((a * b), output);
            }
        }
    }

    type GB<Wire> = Garbler<SwankyRng, ChouOrlandi<Sender>, Wire>;
    type EV<Wire> = Evaluator<SwankyRng, ChouOrlandi<Receiver>, Wire>;

    fn test_aes<C, Wire: WireLabel<F2> + Send>(circ: &C)
    where
        C: CircuitInputMapper<Dummy>
            + CircuitOutputMapper<Dummy>
            + CircuitInputMapper<CircuitAnalyzer>
            + CircuitInputMapper<GB<Wire>>
            + CircuitOutputMapper<GB<Wire>>
            + CircuitInputMapper<EV<Wire>>
            + CircuitOutputMapper<EV<Wire>>
            + Send
            + Sync
            + 'static,
    {
        let mut analyzer = CircuitAnalyzer::new();
        analyzer.eval(circ).unwrap();
        println!("{analyzer}");

        let (_, out) = swanky_channel::local::local_channel_pair(
            |channel| {
                let rng = SwankyRng::new();
                let mut gb = Garbler::<SwankyRng, ChouOrlandi<Sender>, Wire>::new(channel, rng)?;
                let mut xs = gb.encode_many(&[F2::ZERO; 128], channel)?;
                let ys = gb.receive_many(128, channel)?;
                xs.extend(ys);
                let outputs = circ.execute(
                    &mut gb,
                    <C as CircuitInputMapper<GB<_>>>::map(circ, xs),
                    channel,
                )?;
                gb.outputs(
                    &<C as CircuitOutputMapper<GB<_>>>::flatten(outputs),
                    channel,
                )?;
                Ok(())
            },
            |channel| {
                let rng = SwankyRng::new();
                let mut ev =
                    Evaluator::<SwankyRng, ChouOrlandi<Receiver>, Wire>::new(channel, rng)?;
                let mut xs = ev.receive_many(128, channel)?;
                let ys = ev.encode_many(&[F2::ZERO; 128], channel)?;
                xs.extend(ys);
                let wirelabels = circ.execute(
                    &mut ev,
                    <C as CircuitInputMapper<EV<_>>>::map(circ, xs),
                    channel,
                )?;
                let out = ev.outputs(
                    &<C as CircuitOutputMapper<EV<_>>>::flatten(wirelabels),
                    channel,
                )?;
                Ok(out.unwrap())
            },
        )
        .unwrap();

        let target = Dummy::eval(
            circ,
            <C as CircuitInputMapper<Dummy>>::map(circ, vec![DummyVal::new(F2::ZERO); 256]),
        )
        .unwrap();
        let target = <C as CircuitOutputMapper<Dummy>>::flatten(target)
            .into_iter()
            .map(|x| x.val())
            .collect::<Vec<_>>();
        assert_eq!(out, target);
    }

    #[test]
    fn test_aes_binary() {
        let aes = Aes128::new();
        test_aes::<_, WireMod2>(&aes);
    }
}
