use popsicle::psty_payload::{Sender};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    fs::{read_to_string},
    net::{TcpListener, TcpStream},
    time::SystemTime,
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}

fn server_protocol(mut channel: TcpChannel<TcpStream>, absolute_path:&str, nthreads: usize) {
    let start = SystemTime::now();
    let mut rng = AesRng::new();

    let mut aggregates= Vec::new();
    let mut cardinality= Vec::new();
    for thread_id in 0..nthreads{
        let mut path = absolute_path.to_owned().clone();
        path.push_str("thread");
        path.push_str(&thread_id.to_string());

        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output_aggregate.txt")).unwrap();
        let partial_cardinality: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output_cardinality.txt")).unwrap();

        aggregates.push(partial_aggregate);
        cardinality.push(partial_cardinality);
    }

    let path_delta = format!("{}{}", absolute_path, "delta.txt");

    let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
    let _ = psi.compute_aggregates(aggregates, cardinality, &path_delta, &mut channel,&mut rng);

    println!(
        "Sender :: Joining threads results time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: Joining threads results time (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: Joining threads results time  (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
}

pub fn join_aggregates(absolute_path: &str, address: &str, nthreads: usize) {
    let port_prefix = format!("{}{}", address,":3000");
    println!("Server listening on {}", port_prefix);
    let listener = TcpListener::bind(port_prefix).unwrap();


    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                let channel = TcpChannel::new(stream);
                server_protocol(channel, absolute_path, nthreads);
                return;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
