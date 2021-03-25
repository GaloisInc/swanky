use popsicle::psty_payload::{Receiver};

use fancy_garbling::{
    Wire,
};
use scuttlebutt::{AesRng, TcpChannel};

use std::{
    fs::{File, write, read_to_string},
    net::{TcpStream},
    time::SystemTime,
    io::Error,
    path::PathBuf,
};
use serde_json;

fn client_protocol(mut channel: TcpChannel<TcpStream>, path:&mut PathBuf, nthreads: usize, _precision: u32) -> u128{
    let start = SystemTime::now();
    let mut rng = AesRng::new();

    let mut aggregates= Vec::new();
    let mut sum_weights= Vec::new();
    for thread_id in 0..nthreads{
        let mut thread_path = "thread".to_owned();
        thread_path.push_str(&thread_id.to_string());
        path.push(thread_path);

        path.push("output_aggregate.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let partial_aggregate: Vec<Wire> = serde_json::from_str(&read_to_string(path_str).unwrap()).unwrap();
        path.pop();

        path.push("output_sum_weights.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let partial_sum_weights: Vec<Wire> = serde_json::from_str(&read_to_string(path_str).unwrap()).unwrap();
        path.pop();

        aggregates.push(partial_aggregate);
        sum_weights.push(partial_sum_weights);

        path.pop();
    }

    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    let weighted_mean = psi.compute_aggregates(aggregates, sum_weights, &mut channel,&mut rng).unwrap();
    println!("weighted_mean: {:?}", weighted_mean);


    path.pop();
    path.push("result.txt");
    let path_str = path.clone().into_os_string().into_string().unwrap();
    path.pop();

    let _ = File::create(path_str.clone()).unwrap();

    let mut output_write = "Weighted Mean: ".to_owned();
    output_write.push_str(&weighted_mean.to_string());

    write(path_str, output_write).expect("Unable to write file");

    println!(
        "Receiver :: total Joining threads results time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver :: total Joining threads results time (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: total Joining threads results time  (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );

    weighted_mean
}

pub fn join_aggregates(path:&mut PathBuf, address: &str, nthreads: usize, precision: u32) -> Result<u128, Error>{
    let port_prefix = format!("{}{}", address,":3000");

    match TcpStream::connect(port_prefix) {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            Ok(client_protocol(channel, path, nthreads, precision))
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
            Err(e)
        }
    }
}
