use popsicle::psty_payload_large::{Receiver};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    env,
    fs::{File, read_to_string},
    io::Write,
    net::{TcpStream},
    time::SystemTime,
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}

fn client_protocol(mut stream: TcpChannel<TcpStream>, nthreads: usize) {
    let start = SystemTime::now();
    let mut rng = AesRng::new();

    let mut aggregates= Vec::new();
    for thread_id in 0..nthreads{
        let mut path = "./thread".to_owned();
        path.push_str(&thread_id.to_string());

        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output.txt")).unwrap();
        aggregates.push(partial_aggregate);
    }

    let mut psi = Receiver::init(&mut stream, &mut rng).unwrap();
    let output = psi.compute_aggregates(aggregates, &mut stream,&mut rng).unwrap();

    let path_result = "./result.txt".to_owned();
    let mut file_result = File::create(path_result).unwrap();
    file_result.write(&output.to_le_bytes()).unwrap();

    println!("output {:?}", output);
    println!(
        "Receiver :: Joining threads results time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver :: Joining threads results time (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: Joining threads results time  (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );
}

pub fn join_aggregates(nthreads: usize) {
    match TcpStream::connect("0.0.0.0:3000") {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel, nthreads);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
