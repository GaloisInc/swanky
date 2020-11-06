use popsicle::psty_payload_large::{Sender};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, Block, TcpChannel};
extern crate fancy_garbling;
use fancy_garbling::Wire;

use std::{
    fs::{File, create_dir_all},
    io::{Write},
    net::{TcpListener, TcpStream},
    process::{exit},
    collections::HashMap,
};
use serde;
use serde_json;

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
    (0..n).map(|_| rng.gen::<u64>()%modulus).collect()
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
    const ITEM_SIZE: usize = 2;
    const SET_SIZE: usize = 1 << 2;
    const N_THREADS: usize = 2;
    const ELEMENT_SIZES: usize = 64;

    let mut rng = AesRng::new();

    let sender_inputs = enum_ids(SET_SIZE, ITEM_SIZE);

    let weights_vec = rand_u64_vec(SET_SIZE, u64::pow(10,10), &mut rng);
    let weights = int_vec_block512(weights_vec);

    let qs = fancy_garbling::util::primes_with_width(ELEMENT_SIZES as u32);
    let deltas = generate_deltas(&qs);

    let path_delta = "./deltas.txt".to_owned();
    let mut file_deltas = File::create(path_delta).unwrap();
    let deltas_json = serde_json::to_string(&deltas).unwrap();
    file_deltas.write(deltas_json.as_bytes()).unwrap();


    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();

    let (state, _, nmegabins, megasize) = psi.bucketize_data(&sender_inputs, &weights, &mut stream, &mut rng).unwrap();

    let megabin_per_thread = ((nmegabins as f32)/(N_THREADS as f32)).ceil() as usize;

    let ts_id: Vec<&[Block512]>= state.opprf_ids.chunks(megasize).collect();
    let ts_payload: Vec<&[Block512]>= state.opprf_payloads.chunks(megasize).collect();
    let table:Vec<&[Vec<Block>]> = state.table.chunks(megasize).collect();
    let payload: Vec<&[Vec<Block512>]>= state.payload.chunks(megasize).collect();

    let ts_id: Vec<&[&[Block512]]>= ts_id.chunks(megabin_per_thread).collect();
    let ts_payload: Vec<&[&[Block512]]>= ts_payload.chunks(megabin_per_thread).collect();
    let table:Vec<&[&[Vec<Block>]]> = table.chunks(megabin_per_thread).collect();
    let payload: Vec<&[&[Vec<Block512>]]>= payload.chunks(megabin_per_thread).collect();

    for i in 0 ..N_THREADS{
        let mut path = "./thread".to_owned();
        path.push_str(&i.to_string());
        let _ = create_dir_all(path.clone());

        let mut file_ts_id = File::create(format!("{}{}", path, "/ts_id.txt")).unwrap();
        let mut file_ts_payload = File::create(format!("{}{}", path,"/ts_payload.txt")).unwrap();
        let mut file_table = File::create(format!("{}{}", path,"/table.txt")).unwrap();
        let mut file_payload = File::create(format!("{}{}", path,"/payload.txt")).unwrap();

        let ts_id_json = serde_json::to_string(&ts_id[i]).unwrap();
        let ts_payload_json = serde_json::to_string(&ts_payload[i]).unwrap();
        let table_json = serde_json::to_string(&table[i]).unwrap();
        let payload_json = serde_json::to_string(&payload[i]).unwrap();

        file_ts_id.write(ts_id_json.as_bytes()).unwrap();
        file_ts_payload.write(ts_payload_json.as_bytes()).unwrap();
        file_table.write(table_json.as_bytes()).unwrap();
        file_payload.write(payload_json.as_bytes()).unwrap();
    }

}

fn main() {
    let listener = TcpListener::bind("localhost:3000").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                    let channel = TcpChannel::new(stream);
                    server_protocol(channel);
                    exit(0);

            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
