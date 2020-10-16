use popsicle::psty_payload::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TrackChannel};

use std::{
    io::{BufRead, BufReader, BufWriter},
    fs::File,
    os::unix::net::UnixStream,
    time::SystemTime,
};

pub fn int_vec_block512(values: Vec<u32>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..4{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn rand_u32_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u32, rng: &mut RNG) -> Vec<u32>{
    (0..n).map(|_| rng.gen::<u32>()%modulus).collect()
}


pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
    let mut ids = Vec::with_capacity(n);
    for i in 0..n as u64{
        let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}

pub fn read_from_file(file_name: String) -> Vec<Vec<u32>>{
    let mut file = BufReader::new(File::open(file_name).unwrap());
    file.lines()
        .map(|l| l.unwrap().split(",")
                 .map(|number| number.parse().unwrap())
                 .collect())
        .collect()
}

fn protocol(){
    const ITEM_SIZE: usize = 3;
    const SET_SIZE: usize = 1 << 6;

    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();

    let ids_sender = enum_ids(SET_SIZE, ITEM_SIZE);
    let ids_receiver = ids_sender.clone();

    let sender_inputs = ids_sender.clone();
    let receiver_inputs = ids_receiver.clone();

    let payloads = rand_u32_vec(SET_SIZE, 65535, &mut rng);
    let weights = rand_u32_vec(SET_SIZE, 1000000, &mut rng);

    let payloads_sender = int_vec_block512(payloads.clone());
    let payloads_receiver =  int_vec_block512(weights.clone());

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = TrackChannel::new(reader, writer);

        let start = SystemTime::now();
        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
        println!(
            "Sender :: init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );

        let start = SystemTime::now();
        let mut state = psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
        println!(
            "Sender :: send time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: pre-payload communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: pre-payloads communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );

        let start = SystemTime::now();
        state.prepare_payload(&mut psi, &payloads_sender, &mut channel, &mut rng).unwrap();
        println!(
            "Sender :: payload preparation time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: total setup communication (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: total setup communication (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );

        let start = SystemTime::now();
        state.compute_payload_aggregate(&mut channel, &mut rng).unwrap();
        println!(
            "Sender :: total computation and intersection time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender :: total computation and intersection (read): {:.2} Mb",
            channel.kilobits_read() / 1000.0
        );
        println!(
            "Sender :: total computation and intersection (write): {:.2} Mb",
            channel.kilobits_written() / 1000.0
        );

    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = TrackChannel::new(reader, writer);

    let start = SystemTime::now();
    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    println!(
        "Receiver :: init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );

    let start = SystemTime::now();
    let mut state = psi
        .receive(&receiver_inputs, &mut channel, &mut rng)
        .unwrap();
    println!(
        "Receiver :: send time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver :: pre-payload communication (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: pre-payloads communication (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );

    let start = SystemTime::now();
    state.prepare_payload(&mut psi, &payloads_receiver, &mut channel, &mut rng).unwrap();
    println!(
        "Receiver :: payload preparation time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver :: total setup communication (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: total setup communication (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );


    let start = SystemTime::now();
    let output = state.compute_payload_aggregate(&mut channel, &mut rng).unwrap();

    println!(
        "Receiver :: toal computation and intersection time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver :: total computation and intersection (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: total computation and intersection (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );

    handle.join().unwrap();
    println!("Computing Expected Result");
    let mut expected_result: u128= 0;
    for i in 0..SET_SIZE{
        if ids_sender[i] == ids_receiver[i]{
            let ps = payloads[i] as u128;
            let pr = weights[i] as u128;
            expected_result += ps*pr;
        }
    }

    assert_eq!(output as u128, expected_result);
    // let normalized_out = output as f128;
    println!("output {:?}", output);
}

fn main() {
    // read_from_file("values.txt".to_string());
    protocol();
    println!("Success!");
}
