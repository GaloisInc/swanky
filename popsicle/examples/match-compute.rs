use popsicle::psty::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{Channel, AesRng, Block512};

use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

pub fn rand_vec<RNG: CryptoRng + Rng>(n: usize, rng: &mut RNG) -> Vec<u8> {
    (0..n).map(|_| rng.gen()).collect()
}

pub fn rand_vec_vec<RNG: CryptoRng + Rng>(n: usize, m: usize, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n).map(|_| rand_vec(m, rng)).collect()
}

pub fn rand_vec_block512(n: usize) -> Vec<Block512> {
    (0..n).map(|_| Block512::from([1; 64])).collect()
}

fn protocol(){
    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1;

    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
    let receiver_inputs = sender_inputs.clone();
    let payloads_sender =  rand_vec_block512(SET_SIZE);
    let payloads_receiver =  payloads_sender.clone();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

        let mut states = psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
        states.prepare_payload(&mut psi, &payloads_sender, &mut channel, &mut rng).unwrap();
        states.compute_payload_aggregate(&mut channel, &mut rng).unwrap();
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

    let mut state = psi
        .receive(&receiver_inputs, &mut channel, &mut rng)
        .unwrap();
    state.prepare_payload(&mut psi, &payloads_receiver, &mut channel, &mut rng).unwrap();
    // let cardinality = state.compute_intersection(&mut channel, &mut rng).unwrap();
    let output = state.compute_payload_aggregate(&mut channel, &mut rng).unwrap();

    handle.join().unwrap();
    println!("output {:?}", output);
    // assert_eq!(cardinality, SET_SIZE);
}

fn main() {
    protocol();
}
