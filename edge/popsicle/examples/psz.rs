use popsicle::psz::{Receiver, Sender};
use std::time::SystemTime;
use swanky_rng::SwankyRng;

const NBYTES: usize = 16;
const NINPUTS: usize = 1 << 20;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psi(ninputs: usize, nbytes: usize) {
    let sender_inputs = rand_vec_vec(ninputs, nbytes);
    let receiver_inputs = sender_inputs.clone();
    let total = SystemTime::now();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut psi = Sender::init(channel, &mut rng)?;
            println!(
                "Sender :: init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            psi.send(&sender_inputs, channel, &mut rng)?;
            println!(
                "Sender :: send time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut psi = Receiver::init(channel, &mut rng)?;
            println!(
                "Receiver :: init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let _ = psi.receive(&receiver_inputs, channel, &mut rng)?;
            println!(
                "Receiver :: receive time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
    )
    .unwrap();
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    println!(
        "* Running PSZ on {} inputs each of length {} bytes",
        NINPUTS, NBYTES
    );
    psi(NINPUTS, NBYTES);
}
