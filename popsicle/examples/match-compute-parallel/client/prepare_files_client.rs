// Bucketize Data and Seperate it among threads
use popsicle::psty_payload::{Receiver};

use scuttlebutt::{AesRng, Block512, Block, TcpChannel};

use std::{
    fs::{File, create_dir_all},
    io::{Write},
    net::{TcpStream},
    time::SystemTime,
    path::PathBuf,
};

use bincode;


fn client_protocol(mut channel: TcpChannel<TcpStream>, path: &mut PathBuf, nthread: usize,
                    megasize: usize, ids: &[Vec<u8>], payloads: &[Block512]){
    let start = SystemTime::now();

    let mut rng = AesRng::new();


    // The Receiver bucketizes the data and seperates into megabins during the cuckoo hashing.
    // And sends the number of megabins, number of bins etc. to the sender
    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    let (table, payload, nmegabins) = psi.bucketize_data_large(&ids, &payloads, megasize, &mut channel, &mut rng).unwrap();

    let megabin_per_thread = ((nmegabins as f32)/(nthread as f32)).ceil() as usize;

    println!("Number of megabins per thread {:?}", megabin_per_thread);

    let table:Vec<&[Vec<Block>]> = table.chunks(megabin_per_thread).collect();
    let payload: Vec<&[Vec<Block512>]>= payload.chunks(megabin_per_thread).collect();

    // Create files and folders with the data that each thread should handle.
    for i in 0 ..nthread{
        let mut thread_path = "thread".to_owned();
        thread_path.push_str(&i.to_string());
        path.push(thread_path);

        let path_str = path.clone().into_os_string().into_string().unwrap();
        let _ = create_dir_all(path_str);

        path.push("table.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let mut file_table = File::create(path_str).unwrap();
        path.pop();

        path.push("payload.txt");
        let path_str = path.clone().into_os_string().into_string().unwrap();
        let mut file_payload = File::create(path_str).unwrap();
        path.pop();

        let table_json = bincode::serialize(&table[i]).unwrap();
        let payload_json = bincode::serialize(&payload[i]).unwrap();

        file_table.write(&table_json).unwrap();
        file_payload.write(&payload_json).unwrap();

        path.pop();
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

pub fn prepare_files(path: &mut PathBuf, address: &str, nthread: usize, megasize: usize,
                    ids: &[Vec<u8>], payloads: &[Block512]){
    let address = format!("{}{}", address,":3000");

    match TcpStream::connect(address) {
        Ok(stream) => {
            let channel = TcpChannel::new(stream);
            client_protocol(channel, path, nthread, megasize, ids, payloads);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
