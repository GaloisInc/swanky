use popsicle::psty_payload::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TcpChannel};

use std::{
    collections::HashSet,
    time::SystemTime,
};

use std::net::{TcpStream};
use std::str::from_utf8;

pub fn rand_vec<RNG: CryptoRng + Rng>(n: usize, rng: &mut RNG) -> Vec<u8> {
    (0..n).map(|_| rng.gen()).collect()
}

pub fn rand_vec_vec<RNG: CryptoRng + Rng>(n: usize, m: usize, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n).map(|_| rand_vec(m, rng)).collect()
}

pub fn rand_vec_vec_unique<RNG: CryptoRng + Rng>(n: usize, m: usize, rng: &mut RNG, unique:&mut HashSet<Vec<u8>>) -> Vec<Vec<u8>> {
    (0..n).map(|_|{
        let mut r = rand_vec(m, rng);
        while unique.contains(&r) {
            r = rand_vec(m, rng);
        }
        unique.insert(r.clone());
        r
    }).collect()


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


pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
    let mut ids = Vec::with_capacity(n);
    for i in 0..n as u64{
        let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}

fn client_protocol(mut stream: TcpChannel<TcpStream>){
    const ITEM_SIZE: usize = 3;
    const SET_SIZE: usize = 1 << 16;

    let mut rng = AesRng::new();
    let receiver_inputs = enum_ids(SET_SIZE, ITEM_SIZE);
    let payloads = int_vec_block512(rand_u32_vec(SET_SIZE, 65535, &mut rng));

    let mut psi = Receiver::init(&mut stream, &mut rng).unwrap();
    println!("receiving");
    let mut state = psi
        .receive(&receiver_inputs, &mut stream, &mut rng)
        .unwrap();
    println!("done rx");
    state.prepare_payload(&mut psi, &payloads, &mut stream, &mut rng).unwrap();
    println!("done preparing rx");
    let output = state.compute_payload_aggregate(&mut stream, &mut rng).unwrap();
    println!("done computing rx");

}

fn main() {
    match TcpStream::connect("localhost:3000") {
        Ok(mut stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
