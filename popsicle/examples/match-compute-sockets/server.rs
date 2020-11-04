use popsicle::psty_payload_large::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TcpChannel};

use std::{
    net::{TcpListener, TcpStream},
    thread,
    time::SystemTime,
};


pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..8{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u64, rng: &mut RNG) -> Vec<u64>{
    (0..n).map(|_| 100).collect()
    // rng.gen::<u64>()%modulus
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
    const ITEM_SIZE: usize = 16;
    const SET_SIZE: usize = 1 << 7;

    let mut rng = AesRng::new();
    let sender_inputs = enum_ids(SET_SIZE, ITEM_SIZE);
    let weights_vec = rand_u64_vec(SET_SIZE, u64::pow(10,10), &mut rng);
    let weights = int_vec_block512(weights_vec);

    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    let mut state = psi.compute_payload_large(&sender_inputs, &weights, &mut stream, &mut rng).unwrap();

}

fn main() {
    let listener = TcpListener::bind("localhost:3000").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    let stream = TcpChannel::new(stream);
                    server_protocol(stream)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
