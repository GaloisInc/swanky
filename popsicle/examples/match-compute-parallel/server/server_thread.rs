use popsicle::psty_payload::{Sender};

use scuttlebutt::{AesRng, Block, Block512, TcpChannel};

use std::{
    env,
    fs::{File},
    io::{Write, Read},
    net::{TcpListener, TcpStream},
    process::{exit},
    thread,
    time::SystemTime,
};
use serde_json;
use bincode;

fn server_protocol(mut stream: TcpChannel<TcpStream>, thread_id: usize) {
    let start = SystemTime::now();
    println!("Sender Thread {} Starting computation", thread_id);

    let mut rng = AesRng::new();

    let mut path = "./thread".to_owned();
    path.push_str(&thread_id.to_string());

    let mut file_ts_id = File::open(format!("{}{}", path, "/ts_id.txt")).unwrap();
    let mut file_ts_payload = File::open(format!("{}{}", path,"/ts_payload.txt")).unwrap();
    let mut file_table = File::open(format!("{}{}", path,"/table.txt")).unwrap();
    let mut file_payload = File::open(format!("{}{}", path,"/payload.txt")).unwrap();

    let mut buff1= Vec::new();
    let mut buff2= Vec::new();
    let mut buff3= Vec::new();
    let mut buff4= Vec::new();

    file_ts_id.read_to_end(&mut buff1).unwrap();
    file_ts_payload.read_to_end(&mut buff2).unwrap();
    file_table.read_to_end(&mut buff3).unwrap();
    file_payload.read_to_end(&mut buff4).unwrap();

    let ts_id: Vec<Vec<Block512>> = bincode::deserialize(&mut buff1).unwrap();
    let ts_payload: Vec<Vec<Block512>> = bincode::deserialize(&mut buff2).unwrap();
    let table: Vec<Vec<Vec<Block>>> = bincode::deserialize(&mut buff3).unwrap();
    let payload: Vec<Vec<Vec<Block512>>> = bincode::deserialize(&mut buff4).unwrap();

    // let ts_payload: Vec<Vec<Block512>> = bincode::deserialize(&Read::read_to_end().unwrap()).unwrap();
    // let table: Vec<Vec<Vec<Block>>> = bincode::deserialize(&Read::read_to_end(&path, "/table.txt").unwrap()).unwrap();
    // let payload: Vec<Vec<Vec<Block512>>> = bincode::deserialize(&Read::read_to_end(&path, "/payload.txt").unwrap()).unwrap();

    let path_delta = "./deltas.txt".to_owned();
    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    let (acc, card) = psi.compute_payload(ts_id, ts_payload, table, payload, &path_delta, &mut stream, &mut rng).unwrap();

    println!(
        "Sender Thread {} :: circuit building & computation time: {} ms", thread_id,
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender Thread {} :: circuit building & computation communication (read): {:.2} Mb",thread_id,
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Sender Thread {} :: circuit building & computation communication (write): {:.2} Mb",thread_id,
        stream.kilobits_written() / 1000.0
    );

    let mut file_aggregate = File::create(format!("{}{}", path, "/output_aggregate.txt")).unwrap();
    let mut file_cardinality = File::create(format!("{}{}", path, "/output_cardinality.txt")).unwrap();

    let aggregate_json = serde_json::to_string(&acc.wires().to_vec()).unwrap();
    let cardinality_json = serde_json::to_string(&card.wires().to_vec()).unwrap();

    file_aggregate.write(aggregate_json.as_bytes()).unwrap();
    file_cardinality.write(cardinality_json.as_bytes()).unwrap();
}

pub fn server_thread(thread_id: usize) {
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
                return;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
