//! Private set intersection (PSTY) benchmarks using `criterion`.

use popsicle::psty::{Receiver, Sender};
use scuttlebutt::{channel::track_unix_channel_pair, AesRng};
use std::time::SystemTime;

const NBYTES: usize = 16;
const NINPUTS: usize = 1 << 16;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) {
    let (mut tx, mut rx) = track_unix_channel_pair();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();

        let start = SystemTime::now();
        let mut sender = Sender::init(&mut tx, &mut rng).unwrap();
        println!(
            "Sender :: init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let state = sender.send(&inputs1, &mut tx, &mut rng).unwrap();
        println!(
            "Sender :: send time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: pre-circuit communication (read): {:.2} Mb",
            tx.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: pre-circuit communication (write): {:.2} Mb",
            tx.kilobits_written() / 1000.0
        );
        let start = SystemTime::now();
        let _ = state.compute_intersection(&mut tx, &mut rng).unwrap();
        println!(
            "Sender :: intersection time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: total communication (read): {:.2} Mb",
            tx.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: total communication (write): {:.2} Mb",
            tx.kilobits_written() / 1000.0
        );
    });

    let mut rng = AesRng::new();

    let start = SystemTime::now();
    let mut receiver = Receiver::init(&mut rx, &mut rng).unwrap();
    println!(
        "Receiver :: init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let state = receiver.receive(&inputs2, &mut rx, &mut rng).unwrap();
    println!(
        "Receiver :: receive time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = state.compute_intersection(&mut rx, &mut rng).unwrap();
    println!(
        "Receiver :: intersection time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let _ = handle.join().unwrap();
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
        "* Running PSTY on {} inputs each of length {} bytes",
        NINPUTS, NBYTES
    );
    let rs = rand_vec_vec(NINPUTS, NBYTES);
    psty(rs.clone(), rs.clone());
}
