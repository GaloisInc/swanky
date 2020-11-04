use popsicle::psty_payload_large::{Receiver};

use scuttlebutt::{AesRng, Block, Block512, TcpChannel};

use std::{
    env,
    fs::{File, read_to_string},
    io::{Write},
    net::{TcpStream},
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}


fn client_protocol(mut stream: TcpChannel<TcpStream>, thread_id: usize) {
    let mut rng = AesRng::new();

    let mut path = "./thread".to_owned();
    path.push_str(&thread_id.to_string());

    let payload: Vec<Vec<Block512>> = serde_json::from_str(&read_from_file(&path, "/payload.txt")).unwrap();
    let table: Vec<Vec<Block>> = serde_json::from_str(&&read_from_file(&path, "/table.txt")).unwrap();

    let mut psi = Receiver::init(&mut stream, &mut rng).unwrap();
    let acc = psi.compute_payload(table, payload, &mut stream, &mut rng).unwrap();

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

    match TcpStream::connect(port) {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel, thread_id);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
