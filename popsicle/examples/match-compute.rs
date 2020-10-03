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


pub fn int_vec_block512(values: Vec<u32>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..4{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn rand_u32_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u32, rng: &mut RNG) -> Vec<u32>{
    (0..n).map(|_| rng.gen::<u32>()%modulus).collect()
}

pub fn small_change<RNG: CryptoRng + Rng>(vec: &mut Vec<Vec<u8>>, n: usize, rng: &mut RNG)->(){
    for i in 0..n {
        let coin:u8 = rng.gen::<u8>()%2;
        if coin == 0{
            vec[i][0] ^= 1;
        }
    }
}

pub fn shuffle_with_index<RNG: CryptoRng + Rng>(vec: &mut Vec<Vec<u8>>, n: usize, rng: &mut RNG)-> Vec<usize>{
    let mut original_indeces: Vec<usize> = (0..n).collect();

    for i in 0..n{
        let new_index = rng.gen::<usize>()%n;

        let temp = vec[i].clone();
        vec[i] = vec[new_index].clone();
        vec[new_index] = temp;

        let temp = original_indeces[i];
        original_indeces[i] = original_indeces[new_index];
        original_indeces[new_index] = temp;
    }

    original_indeces
}

fn protocol(i: i32){
    const ITEM_SIZE: usize = 2;
    const SET_SIZE: usize = 10;

    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();

    let mut ids_sender = rand_vec_vec(SET_SIZE, ITEM_SIZE,&mut rng);
    let mut ids_receiver = ids_sender.clone();

    small_change(&mut ids_sender, SET_SIZE, &mut rng);
    let original_indeces = shuffle_with_index(&mut ids_receiver, SET_SIZE, &mut rng);

    let sender_inputs = ids_sender.clone();
    let receiver_inputs = ids_receiver.clone();

    let payloads = rand_u32_vec(SET_SIZE, 1000000, &mut rng);
    let weights = rand_u32_vec(SET_SIZE, 1000, &mut rng);

    let payloads_sender = int_vec_block512(payloads.clone());
    let payloads_receiver =  int_vec_block512(weights.clone());

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

        let mut state = psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
        state.prepare_payload(&mut psi, &payloads_sender, &mut channel, &mut rng).unwrap();
        state.compute_payload_aggregate(&mut channel, &mut rng).unwrap();
        // state.compute_cardinality(&mut channel, &mut rng).unwrap();
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

    let mut state = psi
        .receive(&receiver_inputs, &mut channel, &mut rng)
        .unwrap();
    // let cardinality = state.compute_cardinality(&mut channel, &mut rng).unwrap();
    state.prepare_payload(&mut psi, &payloads_receiver, &mut channel, &mut rng).unwrap();
    let output = state.compute_payload_aggregate(&mut channel, &mut rng).unwrap();
    handle.join().unwrap();

    let mut expected_result: u64= 0;
    for i in 0..SET_SIZE{
        if ids_sender[original_indeces[i]] == ids_receiver[i]{
            let ps = payloads[original_indeces[i]] as u64;
            let pr = weights[i] as u64;
            expected_result += ps*pr;
        }
    }
    
    assert_eq!(output as u64, expected_result);
    let normalized_out = output as f64;
    println!("output {:?}", normalized_out /1000.0);

    println!("Trial number {:?} / 10 succeeded.....", i+1);
}

fn main() {
    for i in 0..10{
        protocol(i);
    }
    println!("Success!");
}
