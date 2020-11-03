use popsicle::psty_payload_large::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TcpChannel};

use std::{
    env,
    fs::{File, read_to_string},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::SystemTime,
};
use serde_json::{Result, Value};

fn client_protocol(mut stream: TcpChannel<TcpStream>, thread_id: usize) {

    let mut path = "./examples/match-compute-parallel/client/thread".to_owned();
    path.push_str(&thread_id.to_string());

    let t_path = format!("{}{}", path,"/table.txt");
    let table = read_to_string(t_path).expect("Something went wrong reading the file");
    let table: Value = serde_json::from_str(&table).unwrap();

    println!("table {:?}", table);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let thread_id = args[1].parse::<usize>().unwrap();

    match TcpStream::connect("0.0.0.0:3000") {
        Ok(mut stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel, thread_id);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
