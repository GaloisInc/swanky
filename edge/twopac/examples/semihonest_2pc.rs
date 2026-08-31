use fancy_circuits::crypto::{aes::AesNonExpanded, sha::Sha256CompressionFunctionFixedIV};
use fancy_garbling::WireMod2;
use fancy_traits::{CircuitInputMapper, FancyEncode};
use std::time::SystemTime;
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

fn run_circuit<
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

    let total = SystemTime::now();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng).unwrap();
            println!(
                "Garbler :: Initialization: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let mut xs = gb
                .encode_many(&gb_inputs, &vec![2; n_gb_inputs], channel)
                .unwrap();
            let ys = gb.receive_many(&vec![2; n_ev_inputs], channel).unwrap();
            xs.extend(ys);
            println!(
                "Garbler :: Encoding inputs: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            circ.execute(
                &mut gb,
                <C as CircuitInputMapper<Garbler<SwankyRng, OtSender, WireMod2>>>::map(circ, xs),
                channel,
            )
            .unwrap();
            println!(
                "Garbler :: Circuit garbling: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
        |channel| {
            let rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng).unwrap();
            println!(
                "Evaluator :: Initialization: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let mut xs = ev.receive_many(&vec![2; n_gb_inputs], channel).unwrap();
            let ys = ev
                .encode_many(&ev_inputs, &vec![2; n_ev_inputs], channel)
                .unwrap();
            xs.extend(ys);
            println!(
                "Evaluator :: Encoding inputs: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            circ.execute(
                &mut ev,
                <C as CircuitInputMapper<Evaluator<SwankyRng, OtReceiver, WireMod2>>>::map(
                    circ, xs,
                ),
                channel,
            )
            .unwrap();
            println!(
                "Evaluator :: Circuit evaluation: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
    )
    .unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    let circ = AesNonExpanded::new();
    run_circuit(&circ, vec![0; 128], vec![0; 128]);
    let circ = Sha256CompressionFunctionFixedIV::new();
    run_circuit(&circ, vec![0; 512], vec![]);
}
