use popsicle::psty_payload_large::{Receiver};

use scuttlebutt::{AesRng, Block, Block512, TcpChannel};

use std::{
    env,
    fs::{File},
    io::{Write, Read},
    net::{TcpStream},
    time::SystemTime,
};

use bincode;
use serde_json;

fn client_protocol(mut stream: TcpChannel<TcpStream>, thread_id: usize) {
    let start = SystemTime::now();
    println!("Receiver Thread {} Starting computation", thread_id);
    let mut rng = AesRng::new();

    let mut path = "./thread".to_owned();
    path.push_str(&thread_id.to_string());

    let mut file_table = File::open(format!("{}{}", path,"/table.txt")).unwrap();
    let mut file_payload = File::open(format!("{}{}", path,"/payload.txt")).unwrap();

    let mut buff1= Vec::new();
    let mut buff2= Vec::new();

    file_table.read_to_end(&mut buff1).unwrap();
    file_payload.read_to_end(&mut buff2).unwrap();

    let table: Vec<Vec<Block>> = bincode::deserialize(&mut buff1).unwrap();
    let payload: Vec<Vec<Block512>> = bincode::deserialize(&mut buff2).unwrap();
    let mut psi = Receiver::init(&mut stream, &mut rng).unwrap();
    let acc = psi.compute_payload(table, payload, thread_id, &mut stream, &mut rng).unwrap();

    println!(
        "Receiver Thread {} :: circuit building & computation time: {} ms", thread_id,
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver Thread {} :: circuit building & computation communication (read): {:.2} Mb",thread_id,
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Receiver Thread {} :: circuit building & computation communication (write): {:.2} Mb",thread_id,
        stream.kilobits_written() / 1000.0
    );

    path.push_str("/output.txt");
    let mut file_output = File::create(path).unwrap();
    let output_json = serde_json::to_string(&acc.wires().to_vec()).unwrap();
    file_output.write(output_json.as_bytes()).unwrap();
}

pub fn client_thread(thread_id: usize) {
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
