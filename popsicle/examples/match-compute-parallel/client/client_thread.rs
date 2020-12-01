use popsicle::psty_payload::{Receiver};

use scuttlebutt::{AesRng, Block, Block512, TcpChannel};

use std::{
    fs::{File},
    io::{Write, Read},
    net::{TcpStream},
    time::SystemTime,
    path::PathBuf,
};

use bincode;
use serde_json;

fn client_protocol(mut channel: TcpChannel<TcpStream>, path: &mut PathBuf, thread_id: usize) {
    let start = SystemTime::now();
    println!("Receiver Thread {} Starting computation", thread_id);
    let mut rng = AesRng::new();

    let mut thread_path = "thread".to_owned();
    thread_path.push_str(&thread_id.to_string());
    path.push(thread_path);

    path.push("table.txt");
    let path_str = path.clone().into_os_string().into_string().unwrap();
    let mut file_table = File::open(path_str).unwrap();
    path.pop();

    path.push("payload.txt");
    let path_str = path.clone().into_os_string().into_string().unwrap();
    let mut file_payload = File::open(path_str).unwrap();
    path.pop();

    let mut buff1= Vec::new();
    let mut buff2= Vec::new();

    file_table.read_to_end(&mut buff1).unwrap();
    file_payload.read_to_end(&mut buff2).unwrap();

    let table: Vec<Vec<Block>> = bincode::deserialize(&mut buff1).unwrap();
    let payload: Vec<Vec<Block512>> = bincode::deserialize(&mut buff2).unwrap();

    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    let (acc, card) = psi.compute_payload(table, payload, &mut channel, &mut rng).unwrap();

    println!(
        "Receiver Thread {} :: circuit building & computation time: {} ms", thread_id,
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver Thread {} :: circuit building & computation communication (read): {:.2} Mb",thread_id,
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver Thread {} :: circuit building & computation communication (write): {:.2} Mb",thread_id,
        channel.kilobits_written() / 1000.0
    );

    path.push("output_aggregate.txt");
    let path_str = path.clone().into_os_string().into_string().unwrap();
    let mut file_aggregate = File::create(path_str).unwrap();
    path.pop();

    path.push("output_cardinality.txt");
    let path_str = path.clone().into_os_string().into_string().unwrap();
    let mut file_cardinality = File::create(path_str).unwrap();
    path.pop();

    let aggregate_json = serde_json::to_string(&acc.wires().to_vec()).unwrap();
    let cardinality_json = serde_json::to_string(&card.wires().to_vec()).unwrap();

    file_aggregate.write(aggregate_json.as_bytes()).unwrap();
    file_cardinality.write(cardinality_json.as_bytes()).unwrap();
}

pub fn client_thread(path: &mut PathBuf, address: &str, thread_id: usize) {
    let port_prefix = format!("{}{}", address,":800");
    let port = format!("{}{}", port_prefix, thread_id.to_string());

    match TcpStream::connect(port) {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel, path, thread_id);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
