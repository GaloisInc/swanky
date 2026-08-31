use criterion::{Criterion, criterion_group, criterion_main};
use fancy_analyzer::CircuitAnalyzer;
use fancy_circuits::{
    binary::{TestBinaryAddition, TestBinarySubtraction},
    crypto::aes::Aes128,
    test_circuits::{
        binary::{TestAndGateFanN, TestOrGateFanN, TestXorGateFanN},
        fancy::TestBinaryConstant,
    },
};
use fancy_traits::{CircuitInputMapper, CircuitOutputMapper, FancyEncode, FancyOutput};
use rand::RngExt;
use std::time::Duration;
use swanky_authenticated_garbling::{
    EvaluatorOffline, EvaluatorOnline, GarblerOffline, GarblerValidator, PartyEvaluator,
    PartyGarbler, WirePreProcessor,
};
use swanky_rng::SwankyRng;

fn test_circuit<
    'a,
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<GarblerOffline<'a, C>>
        + CircuitOutputMapper<GarblerOffline<'a, C>>
        + CircuitInputMapper<EvaluatorOnline<'a, C>>
        + CircuitOutputMapper<EvaluatorOnline<'a, C>>
        + CircuitInputMapper<GarblerValidator<'a, C>>
        + Sync,
>(
    inputs_gb: &[u16],
    inputs_ev: &[u16],
    rng_gb: &mut SwankyRng,
    rng_ev: &mut SwankyRng,
    circuit: &'a C,
) {
    let ninputs_gb = inputs_gb.len();
    let ninputs_ev = inputs_ev.len();
    swanky_channel::local::local_channel_pair(
        |c| {
            let gb = GarblerOffline::initialize(circuit, c, rng_gb)?;

            let (outputs, gb) = gb.execute()?;
            let mut gb = gb.finalize(c)?;

            let mut inputs = gb.encode_many(inputs_gb, &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let validator = gb.finalize(c)?;
            let mut validator = validator.validate(inputs, c)?;
            validator.outputs(&outputs, c)
        },
        |c| {
            let ev = EvaluatorOffline::initialize(circuit, c, rng_ev)?;
            let mut ev = ev.finalize(c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(inputs_ev, &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let (outputs, ev) = ev.execute(inputs)?;
            let ev = ev.finalize(c)?;
            let mut ev = ev.validate(c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
}

fn bench_party_construction(c: &mut Criterion) {
    let input_size: usize = 1000;
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let circuit = TestAndGateFanN(input_size);
    c.bench_function("party-construction", move |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| GarblerOffline::initialize(&circuit, c, &mut rng_gb),
                |c| EvaluatorOffline::initialize(&circuit, c, &mut rng_ev),
            )
            .unwrap();
        });
    });
}

fn bench_single_and_gate(c: &mut Criterion) {
    let ninputs_gb = 1;
    let ninputs_ev = 1;
    let circuit = TestAndGateFanN(ninputs_gb + ninputs_ev);
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb)
        .map(|_| rng_gb.random::<u16>() % 2)
        .collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev)
        .map(|_| rng_ev.random::<u16>() % 2)
        .collect();
    c.bench_function(
        &format!("single-and-gate::input-sizes::({},{})", 1, 1),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_constant_gates(c: &mut Criterion) {
    let circuit = TestBinaryConstant;
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..0).map(|_| rng_gb.random::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..0).map(|_| rng_ev.random::<u16>() % 2).collect();
    c.bench_function(
        &format!("test_constant_gates::input-sizes::({},{})", 0, 0),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_and_gate_fan_n(c: &mut Criterion) {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestAndGateFanN(ninputs_gb + ninputs_ev);
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb)
        .map(|_| rng_gb.random::<u16>() % 2)
        .collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev)
        .map(|_| rng_ev.random::<u16>() % 2)
        .collect();
    c.bench_function(
        &format!("and-gate-fan-n::input-sizes::({ninputs_gb},{ninputs_ev})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_or_gate_fan_n(c: &mut Criterion) {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestOrGateFanN(ninputs_gb + ninputs_ev);
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb)
        .map(|_| rng_gb.random::<u16>() % 2)
        .collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev)
        .map(|_| rng_ev.random::<u16>() % 2)
        .collect();
    c.bench_function(
        &format!("or-gate-fan-n::input-sizes::({ninputs_gb},{ninputs_ev})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_xor_gate_fan_n(c: &mut Criterion) {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestXorGateFanN(ninputs_gb + ninputs_ev);

    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb)
        .map(|_| rng_gb.random::<u16>() % 2)
        .collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev)
        .map(|_| rng_ev.random::<u16>() % 2)
        .collect();
    c.bench_function(
        &format!("xor-gate-fan-n::input-sizes::({ninputs_gb},{ninputs_ev})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_binary_addition(c: &mut Criterion) {
    let ninputs = 400;
    let circuit = TestBinaryAddition(ninputs);

    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs).map(|_| rng_gb.random::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs).map(|_| rng_ev.random::<u16>() % 2).collect();
    c.bench_function(
        &format!("binary-addition::input-sizes::({ninputs},{ninputs})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_binary_subtraction(c: &mut Criterion) {
    let ninputs = 400;
    let circuit = TestBinarySubtraction(ninputs);

    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs).map(|_| rng_gb.random::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs).map(|_| rng_ev.random::<u16>() % 2).collect();
    c.bench_function(
        &format!("binary-subtraction::input-sizes::({ninputs},{ninputs})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_aes(c: &mut Criterion) {
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb = (0..128)
        .map(|_| rng_gb.random::<u16>() % 2)
        .collect::<Vec<_>>();
    let inputs_ev = (0..128)
        .map(|_| rng_gb.random::<u16>() % 2)
        .collect::<Vec<_>>();

    let circuit = Aes128::new();
    c.bench_function("aes", move |b| {
        b.iter(|| {
            test_circuit(&inputs_gb, &inputs_ev, &mut rng_gb, &mut rng_ev, &circuit);
        })
    });
}

criterion_group! {
    name = authenticated_garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_party_construction,
    bench_and_gate_fan_n, bench_binary_addition, bench_binary_subtraction,
    bench_constant_gates, bench_or_gate_fan_n, bench_single_and_gate, bench_xor_gate_fan_n,
    bench_aes
}

criterion_main!(authenticated_garbling);
