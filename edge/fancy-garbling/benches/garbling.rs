use criterion::{Criterion, criterion_group, criterion_main};
use fancy_circuits::LinearOram;
use fancy_garbling::{Evaluator, Garbler, WireMod2, classic::GarbledCircuit};
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary};
use rand::RngExt;
use std::{hint::black_box, time::Duration};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

fn bench_garble_binary<
    C: CircuitInputMapper<Garbler<SwankyRng, WireMod2>>
        + CircuitOutputMapper<Garbler<SwankyRng, WireMod2>>,
>(
    c: &mut Criterion,
    name: &str,
    circuit: &C,
) {
    c.bench_function(&format!("garble::{name} (2)"), move |bench| {
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<WireMod2, _, _>(circuit, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_eval_binary<
    C: CircuitInputMapper<Garbler<SwankyRng, WireMod2>>
        + CircuitOutputMapper<Garbler<SwankyRng, WireMod2>>
        + CircuitInputMapper<Evaluator<WireMod2>>
        + CircuitOutputMapper<Evaluator<WireMod2>>,
>(
    c: &mut Criterion,
    name: &str,
    circuit: &C,
) {
    c.bench_function(&format!("eval::{name} (2)"), move |bench| {
        let mut rng = rand::rng();
        let (encoder, gc, _) =
            GarbledCircuit::garble::<WireMod2, _, _>(circuit, SwankyRng::new()).unwrap();
        let inputs = (0..<C as CircuitInputMapper<Garbler<_, _>>>::ninputs(circuit))
            .map(|_| rng.random())
            .collect::<Vec<_>>();
        let xs = encoder.encode_inputs(&inputs);
        bench.iter(|| {
            let ys = gc
                .eval_to_wirelabels(
                    circuit,
                    <C as CircuitInputMapper<Evaluator<_>>>::map(circuit, xs.clone()),
                )
                .unwrap();
            black_box(ys);
        })
    });
}

const MIXED_OP_NUM_OPS: usize = 100_000;

struct MixedOp;
impl<F: FancyBinary> Circuit<F> for MixedOp {
    type Input = F::Item;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        input: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut x = input.clone();
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = backend.and(&x, &x, channel)?;
            } else {
                x = backend.xor(&x, &x);
            }
        }
        Ok(x)
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for MixedOp {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 1);
        inputs[0].clone()
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

impl<F: FancyBinary> CircuitOutputMapper<F> for MixedOp {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        vec![output]
    }
}

fn mixed_op(c: &mut Criterion) {
    bench_garble_binary(c, "mixed_op", &MixedOp);
    bench_eval_binary(c, "mixed_op", &MixedOp);
}

fn linear_oram(c: &mut Criterion) {
    let circuit = LinearOram::<1024>::new(1024);
    bench_garble_binary(c, "linear_oram", &circuit);
    bench_eval_binary(c, "linear_oram", &circuit);
}

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = mixed_op, linear_oram
}

criterion_main!(garbling);
