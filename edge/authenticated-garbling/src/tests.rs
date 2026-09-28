#![cfg(test)]

use crate::preprocesser::WirePreProcessor;
use crate::ps::{PartyEvaluator, PartyGarbler};
use crate::{EvaluatorOffline, EvaluatorOnline, GarblerOffline, GarblerValidator};

use fancy_analyzer::CircuitAnalyzer;
use fancy_circuits::binary::{
    TestBinaryAddition, TestBinaryMultiplication, TestBinarySubtraction, TestBinaryTwosComplement,
};
use fancy_circuits::crypto::aes::Aes128;
use fancy_circuits::test_circuits::binary::{
    TestAndGate, TestAndGateFanN, TestNegateGate, TestOrGateFanN, TestXorGateFanN,
};
use fancy_circuits::test_circuits::fancy_binary_constant::TestBinaryConstant;
use fancy_plaintext::{Dummy, DummyVal};
use fancy_traits::{CircuitInputMapper, CircuitOutputMapper, FancyEncode, FancyOutput};
use rand::RngExt;
use swanky_rng::SwankyRng;

#[test]
fn test_party_construction_passes() {
    let input_size = 400;
    let circuit = TestAndGateFanN(input_size);
    swanky_channel::local::local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            GarblerOffline::initialize(&circuit, c, &mut rng)
        },
        |c| {
            let mut rng = SwankyRng::new();
            EvaluatorOffline::initialize(&circuit, c, &mut rng)
        },
    )
    .unwrap();
}

fn test_circuit<
    'a,
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<GarblerOffline<'a, C>>
        + CircuitOutputMapper<GarblerOffline<'a, C>>
        + CircuitInputMapper<EvaluatorOnline<'a, C>>
        + CircuitOutputMapper<EvaluatorOnline<'a, C>>
        + CircuitInputMapper<Dummy>
        + CircuitOutputMapper<Dummy>
        + CircuitInputMapper<GarblerValidator<'a, C>>
        + Sync,
>(
    ninputs_gb: usize,
    ninputs_ev: usize,
    circuit: &'a C,
) {
    assert_eq!(
        ninputs_gb + ninputs_ev,
        <C as CircuitInputMapper<Dummy>>::ninputs(circuit)
    );

    let mut rng = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb).map(|_| rng.random::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev).map(|_| rng.random::<u16>() % 2).collect();

    let dummy_inputs_gb = inputs_gb
        .iter()
        .map(|x| DummyVal::new(*x, 2))
        .collect::<Vec<_>>();
    let dummy_inputs_ev = inputs_ev
        .iter()
        .map(|x| DummyVal::new(*x, 2))
        .collect::<Vec<_>>();

    let dummy_inputs = [dummy_inputs_gb, dummy_inputs_ev].concat();
    let expected = Dummy::eval(
        circuit,
        <C as CircuitInputMapper<Dummy>>::map(circuit, dummy_inputs),
    )
    .unwrap();
    let expected = <C as CircuitOutputMapper<Dummy>>::flatten(expected)
        .into_iter()
        .map(|x| x.val())
        .collect::<Vec<_>>();

    let (_, outputs) = swanky_channel::local::local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let gb = GarblerOffline::initialize(circuit, c, &mut rng)?;
            let (outputs, gb) = gb.execute()?;
            let mut gb = gb.finalize(c)?;

            let mut inputs = gb.encode_many(&inputs_gb, &vec![2; ninputs_gb], c)?;
            let their = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(their);
            let gb = gb.finalize(c)?;
            let mut gb = gb.validate(inputs, c)?;
            let outputs = gb.outputs(&outputs, c)?;
            assert!(outputs.is_none());
            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let ev = EvaluatorOffline::initialize(circuit, c, &mut rng)?;
            let mut ev = ev.finalize(c)?;

            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&inputs_ev, &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let (outputs, ev) = ev.execute(inputs)?;
            let ev = ev.finalize(c)?;
            let mut ev = ev.validate(c)?;
            let outputs = ev.outputs(&outputs, c)?;
            Ok(outputs.expect("evaluator outputs should not be `None`"))
        },
    )
    .unwrap();
    assert_eq!(outputs, expected)
}

#[test]
fn test_and_gate() {
    let ninputs_gb = 1;
    let ninputs_ev = 1;
    let circuit = TestAndGate;

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_negate_gate_garbler() {
    let ninputs_gb = 1;
    let ninputs_ev = 0;
    let circuit = TestNegateGate;

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_negate_gate_evaluator() {
    let ninputs_gb = 0;
    let ninputs_ev = 1;
    let circuit = TestNegateGate;

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_constant_gates() {
    let circuit = TestBinaryConstant;

    test_circuit(0, 0, &circuit);
}

#[test]
fn test_and_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestAndGateFanN(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_or_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestOrGateFanN(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_xor_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestXorGateFanN(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_binary_addition() {
    let ninputs = 400;
    let circuit = TestBinaryAddition(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}

#[test]
fn test_bin_twos_complement() {
    let ninputs = 64;
    let circuit = TestBinaryTwosComplement(ninputs);

    test_circuit(ninputs, 0, &circuit);
}

#[test]
fn test_binary_subtraction() {
    let ninputs = 64;
    let circuit = TestBinarySubtraction(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}

#[test]
fn test_binary_multiplication() {
    let ninputs = 64;
    let circuit = TestBinaryMultiplication::new(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}

#[test]
fn test_aes() {
    let circuit = Aes128::new();

    test_circuit(128, 128, &circuit);
}
