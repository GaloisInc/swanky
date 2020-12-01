use popsicle::psty_payload::{Sender};

use scuttlebutt::{AesRng, Block512, Block, TcpChannel};
extern crate fancy_garbling;
use fancy_garbling::Wire;

use std::{
    fs::{File, create_dir_all},
    io::{Write},
    net::{TcpListener, TcpStream},
    collections::HashMap,
    time::SystemTime,
};
use bincode;
use serde_json;

pub fn generate_deltas(primes: &[u16]) -> HashMap<u16, Wire> {
    let mut deltas = HashMap::new();
    let mut rng = rand::thread_rng();
    for q in primes{
        deltas.insert(*q, Wire::rand_delta(&mut rng, *q));
    }
    deltas
}

fn server_protocol(mut stream: TcpChannel<TcpStream>, absolute_path: &str, nthread: usize,
                    ids: &[Vec<u8>], payloads: &[Block512]){
    let start = SystemTime::now();
    let path = absolute_path.to_owned();

    let mut rng = AesRng::new();

    let qs = fancy_garbling::util::primes_with_width(64 as u32);// for 64bit inputs and outputs
    let deltas = generate_deltas(&qs);

    let path_delta = format!("{}{}", absolute_path, "delta.txt");

    let mut file_deltas = File::create(path_delta).unwrap();
    let deltas_json = serde_json::to_string(&deltas).unwrap();
    file_deltas.write(deltas_json.as_bytes()).unwrap();


    let mut psi = Sender::init(&mut stream, &mut rng).unwrap();

    let (state, _, nmegabins, megasize) = psi.bucketize_data(&ids, &payloads, &mut stream, &mut rng).unwrap();

    let megabin_per_thread = ((nmegabins as f32)/(nthread as f32)).ceil() as usize;

    let ts_id: Vec<&[Block512]>= state.opprf_ids.chunks(megasize).collect();
    let ts_payload: Vec<&[Block512]>= state.opprf_payloads.chunks(megasize).collect();
    let table:Vec<&[Vec<Block>]> = state.table.chunks(megasize).collect();
    let payload: Vec<&[Vec<Block512>]>= state.payload.chunks(megasize).collect();

    let ts_id: Vec<&[&[Block512]]>= ts_id.chunks(megabin_per_thread).collect();
    let ts_payload: Vec<&[&[Block512]]>= ts_payload.chunks(megabin_per_thread).collect();
    let table:Vec<&[&[Vec<Block>]]> = table.chunks(megabin_per_thread).collect();
    let payload: Vec<&[&[Vec<Block512>]]>= payload.chunks(megabin_per_thread).collect();

    for i in 0 ..nthread{
        let mut path = path.clone();
        path.push_str("thread");
        path.push_str(&i.to_string());
        let _ = create_dir_all(path.clone());

        let mut file_ts_id = File::create(format!("{}{}", path, "/ts_id.txt")).unwrap();
        let mut file_ts_payload = File::create(format!("{}{}", path,"/ts_payload.txt")).unwrap();
        let mut file_table = File::create(format!("{}{}", path,"/table.txt")).unwrap();
        let mut file_payload = File::create(format!("{}{}", path,"/payload.txt")).unwrap();

        let ts_id_json = bincode::serialize(&ts_id[i]).unwrap();
        let ts_payload_json = bincode::serialize(&ts_payload[i]).unwrap();
        let table_json = bincode::serialize(&table[i]).unwrap();
        let payload_json = bincode::serialize(&payload[i]).unwrap();

        file_ts_id.write(&ts_id_json).unwrap();
        file_ts_payload.write(&ts_payload_json).unwrap();
        file_table.write(&table_json).unwrap();
        file_payload.write(&payload_json).unwrap();
    }

    println!(
        "Sender :: Bucketization time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Sender :: Bucketization time (read): {:.2} Mb",
        stream.kilobits_read() / 1000.0
    );
    println!(
        "Sender :: Bucketization time  (write): {:.2} Mb",
        stream.kilobits_written() / 1000.0
    );

}

pub fn prepare_files(absolute_path: &str, address: &str, nthread: usize, ids: &[Vec<u8>], payloads: &[Block512]) {
    let address = format!("{}{}", address,":3000");
    println!("Server listening on {}", address);
    let listener = TcpListener::bind(address).unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                    let channel = TcpChannel::new(stream);
                    server_protocol(channel, absolute_path, nthread, ids, payloads);
                    return;

            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}
