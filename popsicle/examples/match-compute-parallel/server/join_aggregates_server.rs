use popsicle::psty_payload::{Sender};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    fs::{read_to_string},
    net::{TcpListener, TcpStream},
    time::SystemTime,
    path::PathBuf,
};
use serde_json;

fn server_protocol(mut channel: TcpChannel<TcpStream>, path:&mut PathBuf, nthreads: usize) {
    let start = SystemTime::now();
    let mut rng = AesRng::new();

    path.push("delta.txt");
    let path_delta = path.clone().into_os_string().into_string().unwrap();
    path.pop();

    let mut aggregates= Vec::new();
    let mut cardinality= Vec::new();
    let mut sum_weights= Vec::new();
    for thread_id in 0..nthreads{
        let mut thread_path = "thread".to_owned();
        thread_path.push_str(&thread_id.to_string());
        path.push(thread_path);

        path.push("output_aggregate.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_to_string(path_str).unwrap()).unwrap();
        path.pop();

        path.push("output_cardinality.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let partial_cardinality: Vec<Wire> = serde_json::from_str(&read_to_string(path_str).unwrap()).unwrap();
        path.pop();

        path.push("output_sum_weights.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let partial_sum_weights: Vec<Wire> = serde_json::from_str(&read_to_string(path_str).unwrap()).unwrap();
        path.pop();

        aggregates.push(partial_aggregate);
        cardinality.push(partial_cardinality);
        sum_weights.push(partial_sum_weights);

        path.pop();
    }

    let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
    let _ = psi.compute_aggregates(aggregates, cardinality, sum_weights, &path_delta, &mut channel,&mut rng);

    println!(
        "Sender :: total Joining threads results time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: total Joining threads results time (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: total Joining threads results time  (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
}

pub fn join_aggregates(path:&mut PathBuf, address: &str, nthreads: usize) {
    let port_prefix = format!("{}{}", address,":3000");
    println!("Server listening on {}", port_prefix);
    let listener = TcpListener::bind(port_prefix).unwrap();


    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                let channel = TcpChannel::new(stream);
                server_protocol(channel, path, nthreads);
                return;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
