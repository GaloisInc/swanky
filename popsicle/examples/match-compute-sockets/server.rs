use popsicle::psty_payload::{Sender};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TcpChannel};
extern crate fancy_garbling;
use fancy_garbling::Wire;

use std::{
    collections::HashMap,
    fs::{File},
    io::{Write},
    net::{TcpListener, TcpStream},
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

pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, _modulus: u64, _rng: &mut RNG) -> Vec<u64>{
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

pub fn generate_deltas(primes: &[u16]) -> HashMap<u16, Wire> {
    let mut deltas = HashMap::new();
    let mut rng = rand::thread_rng();
    for q in primes{
        deltas.insert(*q, Wire::rand_delta(&mut rng, *q));
    }
    deltas
}

fn server_protocol(mut stream: TcpChannel<TcpStream>) {
    const ITEM_SIZE: usize = 16;
    const SET_SIZE: usize = 100000;

    let mut rng = AesRng::new();
    let sender_inputs = enum_ids(SET_SIZE, ITEM_SIZE);
    let weights_vec = rand_u64_vec(SET_SIZE, u64::pow(10,10), &mut rng);
    let weights = int_vec_block512(weights_vec);

    let qs = fancy_garbling::util::primes_with_width(64);

    let deltas = generate_deltas(&qs);
    let deltas_json = serde_json::to_string(&deltas).unwrap();

    let path_delta = "./deltas.txt".to_owned();
    let mut file_deltas = File::create(&path_delta).unwrap();
    file_deltas.write(deltas_json.as_bytes()).unwrap();

    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    let _ = psi.full_protocol(&sender_inputs, &weights, &mut stream, &mut rng).unwrap();

}


pub fn main(){
    let listener = TcpListener::bind("0.0.0.0:3000").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                    let channel = TcpChannel::new(stream);
                    server_protocol(channel);
                    return;

            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
