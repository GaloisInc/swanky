use popsicle::psz::{Receiver, Sender};
use std::time::SystemTime;
use swanky_rng::SwankyRng;

const NBYTES: usize = 16;
const NINPUTS: usize = 1 << 20;
const PAYLOAD_SIZE: usize = 64;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psz_payload(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) {
    let total = SystemTime::now();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = SwankyRng::new();

            let start = SystemTime::now();
            let mut sender = Sender::init(channel, &mut rng)?;
            println!(
                "Sender :: init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            sender.send_payloads(&inputs1, channel, &mut rng)?;
            println!(
                "Sender :: send time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
        |channel| {
            let mut rng = SwankyRng::new();

            let start = SystemTime::now();
            let mut receiver = Receiver::init(channel, &mut rng)?;
            println!(
                "Receiver :: init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let _ = receiver.receive_payloads(&inputs2, channel, &mut rng)?;
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
        "* Running PSTY on {} inputs each of length {} bytes with {} byte payloads",
        NINPUTS, NBYTES, PAYLOAD_SIZE
    );
    let rs = rand_vec_vec(NINPUTS, NBYTES);
    psz_payload(rs.clone(), rs);
}
