mod prepare_files_client;
mod client_thread;
mod join_aggregates_client;
mod parse_files;
mod test;


use prepare_files_client::prepare_files;
use client_thread::client_thread;
use join_aggregates_client::join_aggregates;
use parse_files::parse_files;

use test::test;

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
    let mut path = env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.pop();
    path.pop();

    path.push("popsicle");
    path.push("examples");
    path.push("match-compute-parallel");
    path.push("configuration.txt");

    let absolute_path = path.clone().into_os_string().into_string().unwrap();
    let configuration = File::open(absolute_path).unwrap();
    let buffer = BufReader::new(configuration).lines();
    let mut parameters = HashMap::new();
    for line in buffer.enumerate(){
        let read_line =  line.1.unwrap();
        if !read_line.is_empty(){
            let line_split = read_line.split(": ").map(|item| item.to_string()).collect::<Vec<String>>();
            parameters.insert(line_split[0].clone(), line_split[1].clone());
        }
    }
   //
    let address = parameters.get("address").unwrap().to_owned();
    let sleeptime = parameters.get("sleeptime").unwrap().parse::<u64>().unwrap();

    let nthread = parameters.get("nthread").unwrap().parse::<usize>().unwrap();
    let megasize = parameters.get("megasize").unwrap().parse::<usize>().unwrap();

    let client_path = parameters.get("data_path_client").unwrap().to_owned();
    let schema_id = parameters.get("schema_client_id").unwrap().to_owned();
    let schema_payload = parameters.get("schema_client_payload").unwrap().to_owned();

    let (ids_client, payloads_client) = parse_files(&schema_id, &schema_payload, &client_path);
   //
    // let mut rng = AesRng::new();
    // let ids_client = enum_ids(100, 16);
    // let payloads_client = int_vec_block512(rand_u64_vec(100, 1000,&mut rng));

    let duration = Duration::from_secs(sleeptime);
   //
   path.pop();
   path.push("client");
   prepare_files(&mut path, &address, nthread, megasize, &ids_client, &payloads_client);
   //
    thread::sleep(duration);

    let mut handle = Vec::new();
    for i in 0..nthread {
        let mut path_thread = path.clone();
        let address_thread = address.clone();
       handle.push(thread::spawn(move || {
           client_thread(&mut path_thread, &address_thread, i);
       }));
   }
   //
   for thread in handle {
        let _ = thread.join(); // maybe consider handling errors propagated from the thread here
    }
   //
    thread::sleep(duration);
    let (_result_aggregate, _result_cardinality) = join_aggregates(&mut path, &address, nthread).unwrap();


    // test results

    // let server_path = parameters.get("data_path_server").unwrap().to_owned();
    // let schema_id = parameters.get("schema_server_id").unwrap().to_owned();
    // let schema_payload = parameters.get("schema_server_payload").unwrap().to_owned();
    //
    // let (ids_server, payloads_server) = parse_files(&schema_id, &schema_payload, &server_path);
    //
    // let (weighted_aggregate, cardinality) = test(&ids_client, &ids_server, &payloads_client, &payloads_server);
    // println!("In the open weighted_aggregate {:?}", weighted_aggregate);
    // println!("In the open cardinality {:?}", cardinality);
    //
    // assert_eq!(weighted_aggregate, result_aggregate);
    // assert_eq!(cardinality, result_cardinality);

}
