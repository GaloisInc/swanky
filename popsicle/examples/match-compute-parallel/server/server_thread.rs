use popsicle::psty_payload_large::{Sender};

use scuttlebutt::{AesRng, Block, Block512, TcpChannel};

use std::{
    env,
    fs::{File, read_to_string},
    io::{Write},
    net::{TcpListener, TcpStream},
    process::{exit},
    thread,
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}

fn server_protocol(mut stream: TcpChannel<TcpStream>, thread_id: usize) {
    let mut rng = AesRng::new();

    let mut path = "./thread".to_owned();
    path.push_str(&thread_id.to_string());

    let ts_id: Vec<Vec<Block512>> = serde_json::from_str(&read_from_file(&path, "/ts_id.txt")).unwrap();
    let ts_payload: Vec<Vec<Block512>> = serde_json::from_str(&read_from_file(&path, "/ts_payload.txt")).unwrap();
    let table: Vec<Vec<Vec<Block>>> = serde_json::from_str(&read_from_file(&path, "/table.txt")).unwrap();
    let payload: Vec<Vec<Vec<Block512>>> = serde_json::from_str(&read_from_file(&path, "/payload.txt")).unwrap();

    let path_delta = "./deltas.txt".to_owned();
    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    let acc = psi.compute_payload(ts_id, ts_payload, table, payload, &path_delta, &mut stream, &mut rng).unwrap();

    path.push_str("/output.txt");
    let mut file_output = File::create(path).unwrap();
    let output_json = serde_json::to_string(&acc.wires()).unwrap();
    file_output.write(output_json.as_bytes()).unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let thread_id = args[1].parse::<usize>().unwrap();
    let port_prefix = "0.0.0.0:800".to_owned();
    let port = format!("{}{}", port_prefix, thread_id.to_string());

    let listener = TcpListener::bind(port).unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 8000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                let handle = thread::spawn(move|| {
                    // connection succeeded
                    let stream = TcpChannel::new(stream);
                    server_protocol(stream, thread_id);
                });
                let _ = handle.join();
                println!("yop");
                exit(0);
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
