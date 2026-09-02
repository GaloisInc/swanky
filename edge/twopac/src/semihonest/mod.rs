//! Implementation of semi-honest two-party computation.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use core::marker::PhantomData;
    use fancy_analyzer::CircuitAnalyzer;
    use fancy_circuits::{
        CrtBundle, CrtGadgets,
        arithmetic::{Constant, Multiplication, ReLU},
        crypto::aes::Aes128,
        test_circuits::arithmetic::TestAddition,
        util::{primes_with_width, product},
    };
    use fancy_garbling::{AllWire, WireLabel, WireMod2};
    use fancy_plaintext::{Dummy, DummyVal};
    use fancy_traits::{
        Circuit, CircuitInputMapper, CircuitOutputMapper, FancyArithmetic, FancyConstant,
        FancyEncode, FancyOutput, FancyProj,
    };
    use rand::RngExt;
    use swanky_channel::Channel;
    use swanky_error::Result;
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

    struct TestCircuit<'a>(PhantomData<&'a ()>);
    impl<'a> TestCircuit<'a> {
        fn new() -> Self {
            TestCircuit(PhantomData)
        }
    }
    impl<'a, F: FancyConstant + FancyArithmetic + FancyProj> Circuit<F> for TestCircuit<'a>
    where
        F::Item: 'a,
    {
        type Input = &'a [CrtBundle<F::Item>];
        type Output = Vec<CrtBundle<F::Item>>;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let mut outputs = Vec::with_capacity(inputs.len());
            for x in inputs.iter() {
                let q = x.composite_modulus();
                let c = Constant::new(1, q).execute(backend, (), channel)?;
                let y = Multiplication::new().execute(backend, (x, &c), channel)?;
                let z = ReLU::new().execute(backend, (&y, "100%", None), channel)?;
                outputs.push(z);
            }
            Ok(outputs)
        }
    }

    #[test]
    fn test_relu() {
        let mut rng = rand::rng();
        let n = 10;
        let ps = primes_with_width(10);
        let q = product(&ps);

        let plaintext = (0..n).map(|_| rng.random::<u128>() % q).collect::<Vec<_>>();

        // Run dummy version.
        let inputs = plaintext
            .iter()
            .map(|x| CrtBundle::from((*x, q)))
            .collect::<Vec<_>>();
        let output = Dummy::eval(&TestCircuit::new(), &inputs).unwrap();
        let expected = output
            .iter()
            .map(|x| CrtBundle::from_crt(x, q))
            .collect::<Vec<_>>();

        // Run 2PC version.
        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let rng = SwankyRng::new();
                let mut gb = Garbler::<SwankyRng, ChouOrlandiSender, AllWire>::new(channel, rng)?;
                let xs = gb.crt_encode_many(&plaintext, q, channel)?;
                let result = TestCircuit::new().execute(&mut gb, &xs, channel)?;
                gb.crt_outputs(&result, channel)?;
                Ok(())
            },
            |channel| {
                let rng = SwankyRng::new();
                let mut ev =
                    Evaluator::<SwankyRng, ChouOrlandiReceiver, AllWire>::new(channel, rng)?;
                let xs = ev.crt_receive_many(n, q, channel)?;
                let result = TestCircuit::new().execute(&mut ev, &xs, channel)?;
                Ok(ev.crt_outputs(&result, channel)?.unwrap())
            },
        )
        .unwrap();
        assert_eq!(result, expected);
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
