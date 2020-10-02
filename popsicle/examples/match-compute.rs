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


pub fn vec8_to_block512(vec: Vec<u8>, item_size: usize) -> Block512{
    let mut res_block = [0 as u8; 64];
    for i in 0..item_size{
        res_block[i] = vec[i];
    }
    Block512::from(res_block)
}

pub fn rand_vec_block512<RNG: CryptoRng + Rng>(n: usize, m: usize, rng: &mut RNG) -> Vec<Block512> {
    let res = rand_vec_vec(n, m , rng);
    res.into_iter().map(|item| vec8_to_block512(item, m)).collect()
}

pub fn i64_to_block512(value: i64)-> Block512{
    let value_bytes = value.to_le_bytes();
    let mut res_block = [0 as u8; 64];
    for i in 0..8{
        res_block[i] = value_bytes[i];
    }
    Block512::from(res_block)
}

pub fn int_vec_block512(values: Vec<i64>) -> Vec<Block512> {
    values.into_iter().map(|item| i64_to_block512(item)).collect()
}

fn protocol(){
    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 2;
    const PAYLOAD_SIZE: usize = 64;

    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
    let receiver_inputs = sender_inputs.clone();


    let values = vec![1 as i64, 1 as i64];
    let payloads_sender = int_vec_block512(values.clone());
    let payloads_receiver =  payloads_sender.clone();

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

        let mut state = psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
        state.prepare_payload(&mut psi, &payloads_sender, &mut channel, &mut rng).unwrap();
        state.compute_payload_aggregate(&mut channel, &mut rng).unwrap();
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
    println!("expected output {:?}", values[0]*values[0] + values[1]*values[1]);
    // assert_eq!(cardinality, SET_SIZE);
}

fn main() {
    protocol();
}
