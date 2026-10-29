use fancy_circuits::crypto::{aes::Aes128, sha::Sha256CompressionFunction};
use fancy_garbling::WireMod2;
use fancy_traits::{CircuitInputMapper, FancyEncode};
use std::time::SystemTime;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{Receiver, Sender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

fn run_circuit<
    C: CircuitInputMapper<Garbler<SwankyRng, IKNP<Sender>, WireMod2>>
        + CircuitInputMapper<Evaluator<SwankyRng, IKNP<Receiver>, WireMod2>>
        + Sync
        + Send,
>(
    circ: &C,
    gb_inputs: Vec<F2>,
    ev_inputs: Vec<F2>,
) {
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();

    let total = SystemTime::now();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut gb = Garbler::<SwankyRng, IKNP<Sender>, WireMod2>::new(channel, rng).unwrap();
            println!(
                "Garbler :: Initialization: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let mut xs = gb.encode_many(&gb_inputs, channel).unwrap();
            let ys = gb.receive_many(n_ev_inputs, channel).unwrap();
            xs.extend(ys);
            println!(
                "Garbler :: Encoding inputs: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            circ.execute(
                &mut gb,
                <C as CircuitInputMapper<Garbler<SwankyRng, IKNP<Sender>, WireMod2>>>::map(
                    circ, xs,
                ),
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
            let mut ev =
                Evaluator::<SwankyRng, IKNP<Receiver>, WireMod2>::new(channel, rng).unwrap();
            println!(
                "Evaluator :: Initialization: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let mut xs = ev.receive_many(n_gb_inputs, channel).unwrap();
            let ys = ev.encode_many(&ev_inputs, channel).unwrap();
            xs.extend(ys);
            println!(
                "Evaluator :: Encoding inputs: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            circ.execute(
                &mut ev,
                <C as CircuitInputMapper<Evaluator<SwankyRng, IKNP<Receiver>, WireMod2>>>::map(
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
    let circ = Aes128::new();
    run_circuit(&circ, vec![F2::ZERO; 128], vec![F2::ZERO; 128]);
    let circ = Sha256CompressionFunction::new();
    run_circuit(&circ, vec![F2::ZERO; 512], vec![F2::ZERO; 256]);
}
