use popsicle::psty_payload::{Receiver};

use scuttlebutt::{AesRng, Block512, Block, TcpChannel};

use std::{
    fs::{File, create_dir_all},
    io::{Write},
    net::{TcpStream},
    time::SystemTime,
};

use bincode;


fn client_protocol(mut channel: TcpChannel<TcpStream>, absolute_path: &str, nthread: usize,
                    megasize: usize, ids: Vec<Vec<u8>>, payloads: Vec<Block512>){
    let start = SystemTime::now();
    let mut path = absolute_path.to_owned();
    path.push_str("thread");

    let mut rng = AesRng::new();


    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    let (cuckoo, table, payload) = psi.bucketize_data_large(&ids, &payloads, megasize, &mut channel, &mut rng).unwrap();

    let megabin_per_thread = ((cuckoo.nmegabins as f32)/(nthread as f32)).ceil() as usize;

    println!("Number of megabins {:?}", megabin_per_thread);

    let table:Vec<&[Vec<Block>]> = table.chunks(megabin_per_thread).collect();
    let payload: Vec<&[Vec<Block512>]>= payload.chunks(megabin_per_thread).collect();

    for i in 0 ..nthread{
        let mut path = path.clone();
        path.push_str(&i.to_string());
        let _ = create_dir_all(path.clone());

        let mut file_table = File::create(format!("{}{}", path,"/table.txt")).unwrap();
        let mut file_payload = File::create(format!("{}{}", path,"/payload.txt")).unwrap();

        let table_json = bincode::serialize(&table[i]).unwrap();
        let payload_json = bincode::serialize(&payload[i]).unwrap();

        file_table.write(&table_json).unwrap();
        file_payload.write(&payload_json).unwrap();
    }
    println!(
        "Receiver :: Bucketization time : {} ms",
        start.elapsed().unwrap().as_millis()
    );
    println!(
        "Receiver ::Bucketization time (read): {:.2} Mb",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receiver :: Bucketization time (write): {:.2} Mb",
        channel.kilobits_written() / 1000.0
    );
}

pub fn prepare_files(absolute_path: &str, address: &str, nthread: usize, megasize: usize,
                    ids: Vec<Vec<u8>>, payloads: Vec<Block512>){
    let address = format!("{}{}", address,":3000");

    match TcpStream::connect(address) {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel, absolute_path, nthread, megasize, ids, payloads);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
