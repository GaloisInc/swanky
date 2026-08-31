//! Benchmarks for semi-honest 2PC using `fancy-garbling`.

use core::time::Duration;
use criterion::{Criterion, criterion_group, criterion_main};
use fancy_circuits::crypto::{aes::AesNonExpanded, sha::Sha256CompressionFunctionFixedIV};
use fancy_garbling::WireMod2;
use fancy_traits::{CircuitInputMapper, FancyEncode};
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

fn bench_circuit<
    C: CircuitInputMapper<Garbler<SwankyRng, OtSender, WireMod2>>
        + CircuitInputMapper<Evaluator<SwankyRng, OtReceiver, WireMod2>>
        + Sync
        + Send,
>(
    circ: &C,
    gb_inputs: Vec<u16>,
    ev_inputs: Vec<u16>,
) {
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng).unwrap();
            let mut xs = gb
                .encode_many(&gb_inputs, &vec![2; n_gb_inputs], channel)
                .unwrap();
            let ys = gb.receive_many(&vec![2; n_ev_inputs], channel).unwrap();
            xs.extend(ys);
            circ.execute(
                &mut gb,
                <C as CircuitInputMapper<Garbler<SwankyRng, OtSender, WireMod2>>>::map(circ, xs),
                channel,
            )
            .unwrap();
            Ok(())
        },
        |channel| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng).unwrap();
            let mut xs = ev.receive_many(&vec![2; n_gb_inputs], channel).unwrap();
            let ys = ev
                .encode_many(&ev_inputs, &vec![2; n_ev_inputs], channel)
                .unwrap();
            xs.extend(ys);
            circ.execute(
                &mut ev,
                <C as CircuitInputMapper<Evaluator<SwankyRng, OtReceiver, WireMod2>>>::map(
                    circ, xs,
                ),
                channel,
            )
            .unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_aes_binary(c: &mut Criterion) {
    let circ = AesNonExpanded::new();
    c.bench_function("twopac::semi-honest (AES-binary)", move |bench| {
        bench.iter(|| bench_circuit(&circ, vec![0u16; 128], vec![0u16; 128]))
    });
}

fn bench_sha_256_binary(c: &mut Criterion) {
    let circ = Sha256CompressionFunctionFixedIV::new();
    c.bench_function("twopac::semi-honest (SHA-256-binary)", move |bench| {
        bench.iter(|| bench_circuit(&circ, vec![0u16; 512], vec![]))
    });
}

criterion_group! {
    name = semihonest;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_aes_binary, bench_sha_256_binary
}

criterion_main!(semihonest);
