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

fn server_protocol(mut stream: TcpChannel<TcpStream>, thread_id: usize) {

    let mut path = "./examples/match-compute-parallel/server/thread".to_owned();
    path.push_str(&thread_id.to_string());

    let t_path = format!("{}{}", path, "/payload.txt");
    // let mut file_ts_payload = File::open(format!("{}{}", path,"/ts_payload.txt")).unwrap();
    // let mut file_table = File::open(format!("{}{}", path,"/table.txt")).unwrap();
    // let mut file_payload = File::open(format!("{}{}", path,"/payload.txt")).unwrap();

    let table = read_to_string(t_path).expect("Something went wrong reading the file");
    let table: Value = serde_json::from_str(&table).unwrap();

    println!("table {:?}", table);

}

fn main() {
    let args: Vec<String> = env::args().collect();
    let thread_id = args[1].parse::<usize>().unwrap();

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
                    server_protocol(stream, thread_id)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
