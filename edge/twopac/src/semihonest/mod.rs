//! Implementation of semi-honest two-party computation.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_analyzer::CircuitAnalyzer;
    use fancy_circuits::{crypto::aes::Aes128, test_circuits::arithmetic::TestAddition};
    use fancy_garbling::{AllWire, WireLabel, WireMod2};
    use fancy_plaintext::{Dummy, DummyVal};
    use fancy_traits::{
        Circuit, CircuitInputMapper, CircuitOutputMapper, FancyEncode, FancyOutput,
    };
    use swanky_ot_chou_orlandi::{Receiver as ChouOrlandiReceiver, Sender as ChouOrlandiSender};
    use swanky_rng::SwankyRng;

    #[test]
    fn test_addition() {
        let modulus = 3;
        let circuit = TestAddition(modulus);
        for a in 0..2 {
            for b in 0..2 {
                let (_, output) = swanky_channel::local::local_channel_pair(
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut gb =
                            Garbler::<SwankyRng, ChouOrlandiSender, AllWire>::new(channel, rng)?;
                        let x = gb.encode(a, modulus, channel)?;
                        let y = gb.receive(modulus, channel)?;
                        let outputs = circuit.execute(&mut gb, (x, y), channel)?;
                        let result = gb.output(&outputs, channel)?;
                        assert!(result.is_none());
                        Ok(())
                    },
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut ev = Evaluator::<SwankyRng, ChouOrlandiReceiver, AllWire>::new(
                            channel, rng,
                        )?;
                        let x = ev.receive(modulus, channel)?;
                        let y = ev.encode(b, modulus, channel)?;
                        let output = circuit.execute(&mut ev, (x, y), channel)?;
                        let result = ev.output(&output, channel)?;
                        Ok(result.unwrap())
                    },
                )
                .unwrap();
                assert_eq!((a + b) % modulus, output);
            }
        }
    }

    type GB<Wire> = Garbler<SwankyRng, ChouOrlandiSender, Wire>;
    type EV<Wire> = Evaluator<SwankyRng, ChouOrlandiReceiver, Wire>;

    fn test_aes<C, Wire: WireLabel + Send>(circ: &C)
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
                let mut gb = Garbler::<SwankyRng, ChouOrlandiSender, Wire>::new(channel, rng)?;
                let mut xs = gb.encode_many(&vec![0; 128], &vec![2; 128], channel)?;
                let ys = gb.receive_many(&vec![2; 128], channel)?;
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
                let mut ev = Evaluator::<SwankyRng, ChouOrlandiReceiver, Wire>::new(channel, rng)?;
                let mut xs = ev.receive_many(&vec![2; 128], channel)?;
                let ys = ev.encode_many(&vec![0; 128], &vec![2; 128], channel)?;
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
            <C as CircuitInputMapper<Dummy>>::map(circ, vec![DummyVal::new(0, 2); 256]),
        )
        .unwrap();
        let target = <C as CircuitOutputMapper<Dummy>>::flatten(target)
            .into_iter()
            .map(|x| x.val())
            .collect::<Vec<_>>();
        assert_eq!(out, target);
    }

    #[test]
    fn test_aes_arithmetic() {
        let aes = Aes128::new();
        test_aes::<_, AllWire>(&aes);
    }

    #[test]
    fn test_aes_binary() {
        let aes = Aes128::new();
        test_aes::<_, WireMod2>(&aes);
    }
}
