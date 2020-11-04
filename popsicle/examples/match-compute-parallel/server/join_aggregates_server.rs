use popsicle::psty_payload_large::{Sender};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    env,
    fs::{read_to_string},
    net::{TcpListener, TcpStream},
    process::{exit},
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}

fn server_protocol(mut stream: TcpChannel<TcpStream>, nthreads: usize) {
    let mut rng = AesRng::new();

    let mut aggregates= Vec::new();
    for thread_id in 0..nthreads{
        let mut path = "./thread".to_owned();
        path.push_str(&thread_id.to_string());

        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output.txt")).unwrap();
        aggregates.push(partial_aggregate);
    }

    let path_delta = "./deltas.txt".to_owned();
    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    let output = psi.compute_aggregates(aggregates, &path_delta, &mut stream,&mut rng);

    println!("output {:?}", output);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let nthreads = args[1].parse::<usize>().unwrap();

    let listener = TcpListener::bind("localhost:3000").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                let stream = TcpChannel::new(stream);
                server_protocol(stream, nthreads);
                exit(0);
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
