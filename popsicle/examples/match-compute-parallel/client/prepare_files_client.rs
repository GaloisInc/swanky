use popsicle::psty_payload_test::{Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, Block, TcpChannel};

use std::{
    fs::{File, create_dir_all},
    io::{Write},
    net::{TcpStream},
    time::SystemTime,
};

use bincode;

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
    (0..n).map(|_| 1000000).collect()
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



fn client_protocol(mut stream: TcpChannel<TcpStream>){
    let start = SystemTime::now();
    const ITEM_SIZE: usize = 16;
    const SET_SIZE: usize = 1<<7;
    const MEGA_SIZE:usize = 10;
    const N_THREADS: usize = 4;


    let mut rng = AesRng::new();
    let receiver_inputs = enum_ids(SET_SIZE, ITEM_SIZE);
    let payloads = int_vec_block512(rand_u64_vec(SET_SIZE, u64::pow(10,6), &mut rng));

    let mut psi = Receiver::init(&mut stream, &mut rng).unwrap();
    let (cuckoo, table, payload) = psi.bucketize_data_large(&receiver_inputs, &payloads, MEGA_SIZE, &mut stream, &mut rng).unwrap();

    let megabin_per_thread = ((cuckoo.nmegabins as f32)/(N_THREADS as f32)).ceil() as usize;
    println!("Number of megabins {:?}", megabin_per_thread);
    let table:Vec<&[Vec<Block>]> = table.chunks(megabin_per_thread).collect();
    let payload: Vec<&[Vec<Block512>]>= payload.chunks(megabin_per_thread).collect();

    for i in 0 ..N_THREADS{
        let mut path = "./thread".to_owned();
        path.push_str(&i.to_string());
        let _ = create_dir_all(path.clone());

        let mut file_table = File::create(format!("{}{}", path,"/table.txt")).unwrap();
        let mut file_payload = File::create(format!("{}{}", path,"/payload.txt")).unwrap();

        let table_json = bincode::serialize(&table[i]).unwrap();
        let payload_json = bincode::serialize(&payload[i]).unwrap();

        file_table.write(&table_json).unwrap();
        file_payload.write(&payload_json).unwrap();
    }
    println!(
        "Receiver :: Bucketization time : {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver ::Bucketization time (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: Bucketization time (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );
}

pub fn prepare_files() {
    match TcpStream::connect("0.0.0.0:3000") {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
