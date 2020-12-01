use popsicle::psty_payload::{Receiver};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    fs::{File, read_to_string},
    io::Write,
    net::{TcpStream},
    time::SystemTime,
    io::Error,
};
use serde_json;

fn read_from_file(path: &str, file_name: &str)-> String{
    let data_path = format!("{}{}", path, file_name);
    read_to_string(data_path).unwrap()
}

fn client_protocol(mut channel: TcpChannel<TcpStream>, absolute_path:&str, nthreads: usize) -> (u64, u64){
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

    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    let (aggregate, cardinality) = psi.compute_aggregates(aggregates, cardinality, &mut channel,&mut rng).unwrap();
    let output = aggregate as f64 / cardinality as f64;
    println!("aggregate: {:?}", aggregate);
    println!("cardinality: {:?}", cardinality);
    println!("average: {:?}", output);

    let mut path_result = absolute_path.to_owned().clone();
    path_result.push_str("result.txt");
    let mut file_result = File::create(path_result).unwrap();
    file_result.write(&output.to_le_bytes()).unwrap();


    println!(
        "Receiver :: Joining threads results time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver :: Joining threads results time (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: Joining threads results time  (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );

    (aggregate, cardinality)
}

pub fn join_aggregates(absolute_path: &str, address: &str, nthreads: usize) -> Result<(u64, u64), Error>{
    let port_prefix = format!("{}{}", address,":3000");

    match TcpStream::connect(port_prefix) {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            Ok(client_protocol(channel, absolute_path, nthreads))
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
            Err(e)
        }
    }
}
