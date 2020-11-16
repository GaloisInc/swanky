use popsicle::psty_payload::{Receiver};

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
    let mut cardinality= Vec::new();
    for thread_id in 0..nthreads{
        let mut path = "./thread".to_owned();
        path.push_str(&thread_id.to_string());

        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output_aggregate.txt")).unwrap();
        let partial_cardinality: Vec<Wire> = serde_json::from_str(&read_from_file(&path, "/output_cardinality.txt")).unwrap();

        aggregates.push(partial_aggregate);
        cardinality.push(partial_cardinality);
    }

    let mut psi = Receiver::init(&mut stream, &mut rng).unwrap();
    let (aggregate, cardinality) = psi.compute_aggregates(aggregates, cardinality, &mut stream,&mut rng).unwrap();
    let output = aggregate as f64 / cardinality as f64;
    println!("aggregate: {:?}", aggregate);
    println!("cardinality: {:?}", cardinality);
    println!("average: {:?}", output);

    let path_result = "./result.txt".to_owned();
    let mut file_result = File::create(path_result).unwrap();
    file_result.write(&output.to_le_bytes()).unwrap();


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
