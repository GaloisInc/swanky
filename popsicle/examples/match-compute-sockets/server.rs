use popsicle::psty_payload::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TcpChannel};

use std::{
    net::{TcpListener, TcpStream},
    thread,
    time::SystemTime,
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

pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
    let mut ids = Vec::with_capacity(n);
    for i in 0..n as u64{
        let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}


fn server_protocol(mut stream: TcpChannel<TcpStream>) {
    const ITEM_SIZE: usize = 3;
    const SET_SIZE: usize = 1 << 16;

    let mut rng = AesRng::new();
    let sender_inputs = enum_ids(SET_SIZE, ITEM_SIZE);
    let weights_vec = rand_u32_vec(SET_SIZE, 1000000, &mut rng);
    let weights = int_vec_block512(weights_vec);

    let start = SystemTime::now();
    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    println!(
        "Sender :: init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let mut state = psi.send(&sender_inputs, &mut stream, &mut rng).unwrap();
    println!(
        "Sender :: send time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: intersection setup communication (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: intersection setup communication (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );

    let start = SystemTime::now();
    state.prepare_payload(&mut psi, &weights, &mut stream, &mut rng).unwrap();
    println!(
        "Sender :: payload setup time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: payload setup communication (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: payload setup communication (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );


    let start = SystemTime::now();
    state.compute_payload_aggregate(&mut stream, &mut rng).unwrap();
    println!(
        "Sender :: circuit computation time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: total computation and intersection (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: total computation and intersection (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );

}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:3000").unwrap();
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
