use popsicle::psty_payload::{Sender};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    env,
    fs::{read_to_string},
    net::{TcpListener, TcpStream},
    process::{exit},
    time::SystemTime,
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}

fn server_protocol(mut stream: TcpChannel<TcpStream>, nthreads: usize) {
    let start = SystemTime::now();
    let mut rng = AesRng::new();

    let mut aggregates= Vec::new();
    let mut cardinality= Vec::new();
    for thread_id in 0..nthreads{
        let mut path = "./thread".to_owned();
        path.push_str(&thread_id.to_string());

        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output_aggregate.txt")).unwrap();
        let partial_cardinality: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output_cardinality.txt")).unwrap();

        aggregates.push(partial_aggregate);
        cardinality.push(partial_cardinality);
    }

    let path_delta = "./deltas.txt".to_owned();
    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();
    psi.compute_aggregates(aggregates, cardinality, &path_delta, &mut stream,&mut rng);

    println!(
        "Sender :: Joining threads results time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: Joining threads results time (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: Joining threads results time  (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );
}

pub fn join_aggregates(nthreads: usize) {
    let listener = TcpListener::bind("0.0.0.0:3000").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                let stream = TcpChannel::new(stream);
                server_protocol(stream, nthreads);
                return;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
