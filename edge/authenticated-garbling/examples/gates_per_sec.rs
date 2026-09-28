use fancy_analyzer::CircuitAnalyzer;
use fancy_circuits::LinearOram;
use fancy_garbling::{
    Evaluator as SemiHonestEvaluator, Garbler as SemiHonestGarbler, WireMod2,
    classic::GarbledCircuit,
};
use fancy_traits::{
    Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyEncode, FancyOutput,
};
use std::{hint::black_box, time::Instant};
use swanky_authenticated_garbling::{
    EvaluatorOffline, EvaluatorOnline, GarblerOffline, GarblerValidator, PartyEvaluator,
    PartyGarbler, WirePreProcessor,
};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

struct And(usize);
impl<F: FancyBinary> Circuit<F> for And {
    type Input = (F::Item, F::Item);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut z = backend.and(&inputs.0, &inputs.1, channel)?;
        for _ in 0..self.0 {
            z = backend.and(&z, &inputs.1, channel)?;
        }
        Ok(z)
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for And {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 2);
        (inputs[0].clone(), inputs[1].clone())
    }

    fn ninputs(&self) -> usize {
        2
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

impl<F: FancyBinary> CircuitOutputMapper<F> for And {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        vec![output]
    }
}

fn stats<'a, C>(name: &str, circuit: &'a C) -> Result<()>
where
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<SemiHonestGarbler<SwankyRng, WireMod2>>
        + CircuitOutputMapper<SemiHonestGarbler<SwankyRng, WireMod2>>
        + CircuitInputMapper<SemiHonestEvaluator<WireMod2>>
        + CircuitOutputMapper<SemiHonestEvaluator<WireMod2>>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<GarblerValidator<'a, C>>
        + CircuitInputMapper<GarblerOffline<'a, C>>
        + CircuitOutputMapper<GarblerOffline<'a, C>>
        + CircuitInputMapper<EvaluatorOnline<'a, C>>
        + CircuitOutputMapper<EvaluatorOnline<'a, C>>
        + Sync,
{
    let mut analyzer = CircuitAnalyzer::new();
    analyzer.eval(circuit)?;
    let nands = analyzer.nands();

    let inputs = (0..<C as CircuitInputMapper<CircuitAnalyzer>>::ninputs(circuit))
        .map(|_| 0)
        .collect::<Vec<u16>>();
    let moduli = (0..<C as CircuitInputMapper<CircuitAnalyzer>>::ninputs(circuit))
        .map(|_| 2)
        .collect::<Vec<u16>>();

    println!("*");
    println!("* Circuit: {name} | # ANDs: {nands}");
    println!("*");

    println!("=== Classic Garbling ===");
    let t = Instant::now();
    let (encoder, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(circuit, SwankyRng::new())?;
    let time = t.elapsed();
    println!("Garbler: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    let xs = encoder.encode_inputs(&inputs);
    let t = Instant::now();
    let ys = gc.eval_to_wirelabels(
        circuit,
        <C as CircuitInputMapper<SemiHonestEvaluator<_>>>::map(circuit, xs.clone()),
    )?;
    black_box(ys);
    let time = t.elapsed();
    println!("Evaluator: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    println!("=== Streaming Garbling ===");

    let mut gb = SemiHonestGarbler::<_, WireMod2>::new(SwankyRng::new());
    let mut ev = SemiHonestEvaluator::<WireMod2>::new();
    let ((mut gb, zeros), (mut ev, wires)) = swanky_channel::local::local_channel_pair(
        |channel| {
            let zeros = gb.encode_many(&inputs, &moduli, channel)?;
            Ok((gb, zeros))
        },
        |channel| {
            let wires = ev.receive_many(&moduli, channel)?;
            Ok((ev, wires))
        },
    )?;

    let t = Instant::now();
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let outputs = circuit.execute(
                &mut gb,
                <C as CircuitInputMapper<SemiHonestGarbler<_, _>>>::map(circuit, zeros),
                channel,
            )?;
            gb.outputs(
                &<C as CircuitOutputMapper<SemiHonestGarbler<_, _>>>::flatten(outputs),
                channel,
            )?;
            Ok(())
        },
        |channel| {
            let outputs = circuit.execute(
                &mut ev,
                <C as CircuitInputMapper<SemiHonestEvaluator<_>>>::map(circuit, wires),
                channel,
            )?;
            Ok(ev
                .outputs(
                    &<C as CircuitOutputMapper<SemiHonestEvaluator<_>>>::flatten(outputs),
                    channel,
                )?
                .unwrap())
        },
    )?;
    black_box(result);
    let time = t.elapsed();
    println!("Garbler: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    println!("=== Authenticated Garbling ===");
    let total = Instant::now();
    let offline = Instant::now();
    let ((mut gb, outputs), mut ev) = swanky_channel::local::local_channel_pair(
        |channel: &mut Channel<'_>| {
            let gb = GarblerOffline::initialize(circuit, channel, &mut SwankyRng::new())?;
            let (outputs, gb) = gb.execute()?;
            let gb = gb.finalize(channel)?;
            Ok((gb, outputs))
        },
        |channel| {
            let ev = EvaluatorOffline::initialize(circuit, channel, &mut SwankyRng::new())?;
            let ev = ev.finalize(channel)?;
            Ok(ev)
        },
    )?;
    println!("Offline: {:?}", offline.elapsed());

    let online = Instant::now();
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let inputs = gb.encode_many(&inputs, &moduli, channel)?;
            let validator = gb.finalize(channel)?;
            let mut validator = validator.validate(inputs, channel)?;
            validator.outputs(&outputs, channel)
        },
        |channel| {
            let inputs = ev.receive_many(&moduli, channel)?;
            let (outputs, ev) = ev.execute(inputs)?;
            let ev = ev.finalize(channel)?;
            let mut ev = ev.validate(channel)?;
            ev.outputs(&outputs, channel)
        },
    )?;
    black_box(result);
    println!("Online: {:?}", online.elapsed());

    let time = total.elapsed();
    println!("Total: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    Ok(())
}

fn main() -> swanky_error::Result<()> {
    stats("AND", &And(1_000_000))?;
    stats("Linear ORAM", &LinearOram::<1024>::new(1024))?;
    Ok(())
}
