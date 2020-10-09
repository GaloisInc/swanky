use popsicle::psty::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TcpChannel};

use std::{
    net::{TcpListener, TcpStream},
    thread,
    collections::HashSet,
};

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

pub fn int_vec_block512(values: Vec<u16>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..2{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn rand_u16_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u16, rng: &mut RNG) -> Vec<u16>{
    (0..n).map(|_| rng.gen::<u16>()%modulus).collect()
}

pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
    let mut ids = Vec::with_capacity(n);
    for i in 0..n as u64{
        let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}


fn server_protocol(mut stream: TcpChannel<TcpStream>) {
    const ITEM_SIZE: usize = 1;
    const SET_SIZE: usize = 1;

    let mut rng = AesRng::new();
    let sender_inputs = enum_ids(SET_SIZE, ITEM_SIZE);
    let weights = int_vec_block512(rand_u16_vec(SET_SIZE, 100, &mut rng));

    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
        println!("sending");
    let mut state = psi.send(&sender_inputs, &mut stream, &mut rng).unwrap();
        println!("done sx");
    state.prepare_payload(&mut psi, &weights, &mut stream, &mut rng).unwrap();
    println!("done preparing sx");
    state.compute_payload_aggregate(&mut stream, &mut rng).unwrap();
    println!("done computing sx");

}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    let channel = TcpChannel::new(stream);
                    server_protocol(channel)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
