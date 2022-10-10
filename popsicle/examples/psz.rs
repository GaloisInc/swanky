use popsicle::psz::{Receiver, Sender};
use scuttlebutt::{channel::track_unix_channel_pair, AesRng};
use std::time::SystemTime;

const NBYTES: usize = 16;
const NINPUTS: usize = 1 << 20;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psi(ninputs: usize, nbytes: usize) {
    let (mut tx, mut rx) = track_unix_channel_pair();
    let sender_inputs = rand_vec_vec(ninputs, nbytes);
    let receiver_inputs = sender_inputs.clone();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let start = SystemTime::now();
        let mut psi = Sender::init(&mut tx, &mut rng).unwrap();
        println!(
            "Sender :: init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        psi.send(&sender_inputs, &mut tx, &mut rng).unwrap();
        println!(
            "Sender :: send time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: communication (read): {:.2} Mb",
            tx.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: communication (write): {:.2} Mb",
            tx.kilobits_written() / 1000.0
        );
    });
    let mut rng = AesRng::new();
    let start = SystemTime::now();
    let mut psi = Receiver::init(&mut rx, &mut rng).unwrap();
    println!(
        "Receiver :: init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = psi.receive(&receiver_inputs, &mut rx, &mut rng).unwrap();
    println!(
        "Receiver :: receive time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!(
        "Receiver :: communication (read): {:.2} Mb",
        rx.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: communication (write): {:.2} Mb",
        rx.kilobits_written() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    println!(
        "* Running PSZ on {} inputs each of length {} bytes",
        NINPUTS, NBYTES
    );
    psi(NINPUTS, NBYTES);
}
