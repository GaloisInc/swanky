mod prepare_files_client;
mod client_thread;
mod join_aggregates_client;
mod parse_files;


use prepare_files_client::prepare_files;
use client_thread::client_thread;
use join_aggregates_client::join_aggregates;
use parse_files::parse_files;

use std::{
    env,
    fs::{File},
    io::{BufRead, BufReader},
    collections::HashMap,
    time::{Duration},
    thread,
};

// use rand::{CryptoRng, Rng};
// use scuttlebutt::{AesRng, Block512};
//
// pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
//     values.into_iter()
//           .map(|item|{
//             let value_bytes = item.to_le_bytes();
//             let mut res_block = [0 as u8; 64];
//             for i in 0..8{
//                 res_block[i] = value_bytes[i];
//             }
//             Block512::from(res_block)
//          }).collect()
// }
//
// pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, _modulus: u64, _rng: &mut RNG) -> Vec<u64>{
//     (0..n).map(|_| 1000000).collect()
//     // rng.gen::<u64>()%modulus
// }
//
// pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
//     let mut ids = Vec::with_capacity(n);
//     for i in 0..n as u64{
//         let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
//         ids.push(v);
//     }
//     ids
// }

pub fn main(){
    let mut absolute_path = env::current_exe().unwrap();
    absolute_path.pop();
    absolute_path.pop();
    absolute_path.pop();
    absolute_path.pop();
    absolute_path.pop();

    let mut absolute_path = absolute_path.into_os_string().into_string().unwrap();//
    absolute_path.push_str("/swanky/popsicle/examples/match-compute-parallel/");
    let configuration = File::open(format!("{}{}", absolute_path, "configuration.txt")).unwrap();

    let buffer = BufReader::new(configuration).lines();

    let mut parameters = HashMap::new();
    for line in buffer.enumerate(){
        let line_split = line.1.unwrap().split(": ").map(|item| item.to_string()).collect::<Vec<String>>();
        parameters.insert(line_split[0].clone(), line_split[1].clone());
    }
    let address = parameters.get("address").unwrap().to_owned();
    let nthread = parameters.get("nthread").unwrap().parse::<usize>().unwrap();
    let megasize = parameters.get("megasize").unwrap().parse::<usize>().unwrap();
    let sleeptime = parameters.get("sleeptime").unwrap().parse::<u64>().unwrap();
    let client_path = parameters.get("data_path_client").unwrap().to_owned();

    let duration = Duration::from_secs(sleeptime);

    let (ids, payloads) = parse_files("ID", "PELLAMT", &client_path);

    // let mut rng = AesRng::new();
    // let ids = enum_ids(100000, 16);
    // let payloads = int_vec_block512(rand_u64_vec(100000, 1000,&mut rng));

    absolute_path.push_str("client/");
    prepare_files(&absolute_path, &address, nthread, megasize, ids, payloads);

    thread::sleep(duration);

    let mut handle = Vec::new();
    for i in 0..nthread {
        let absolute_path_thread = absolute_path.clone();
        let address_thread = address.clone();
       handle.push(thread::spawn(move || {
           client_thread(&absolute_path_thread, &address_thread, i);
       }));
   }

   for thread in handle {
        let _ = thread.join(); // maybe consider handling errors propagated from the thread here
    }

    thread::sleep(duration);
    join_aggregates(&absolute_path, &address, nthread);
}
