use popsicle::psty_payload::{Sender, Receiver};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesRng, Block512, TrackChannel};

use std::{
    io::{BufReader, BufWriter},
    // fs::File,
    os::unix::net::UnixStream,
    time::SystemTime,
};

pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..8{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u64, rng: &mut RNG) -> Vec<u64>{
    (0..n).map(|_| rng.gen::<u64>()%modulus).collect()
}

pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
    let mut ids = Vec::with_capacity(n);
    for i in 0..n as u64{
        let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}

fn test(vec: Vec<u64>)-> u64{
    let mut res = 0;
    for el in vec{
        res += el*el;
    }
    res
}

fn protocol(){
    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 15;
    const MEGASIZE: usize = 1000;

    let mut rng = AesRng::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let values = rand_u64_vec(SET_SIZE, u64::pow(10,6), &mut rng);

    let sender_ids = enum_ids(SET_SIZE, ITEM_SIZE);
    let sender_payloads = int_vec_block512(values);

    let receiver_ids = sender_inputs.clone();
    let receiver_payloads = sender_payloads.clone();

    std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);

        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
        let _ = psi.full_protocol_large(&sender_ids, &sender_payloads, &mut channel, &mut rng).unwrap();
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

    let aggregate = psi
        .full_protocol_large(&receiver_ids, &receiver_payloads, MEGASIZE, &mut channel, &mut rng)
        .unwrap();
    assert_eq!(aggregate, test(values));
}

fn main() {
    // read_from_file("values.txt".to_string());
    protocol();
    println!("Success!");
}
