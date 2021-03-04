mod prepare_files_client;
mod client_thread;
mod join_aggregates_client;
mod parse_files;
mod test;


use prepare_files_client::prepare_files;
use client_thread::client_thread;
use join_aggregates_client::join_aggregates;
use parse_files::parse_files;

use test::test;

use std::{
    env,
    fs::{File, write, read_to_string},
    io::{BufRead, BufReader, stdin, stdout, Read, Write},
    collections::HashMap,
    time::{Duration},
    thread,
};
// Alternatively uncomment this section to randomly generate the inputs.
//
// use rand::{CryptoRng, Rng};
// use scuttlebutt::{AesRng, Block512};

// pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
//     values.into_iter()
//           .map(|item|{
//             let value_bytes = item.to_le_bytes();
//             let mut res_block = [0 as u8; 64];
//             for i in 0..8{
//                 res_block[i] = value_bytes[i];
//             }
//             Block512::from(res_block)
//          }).collect()
// }
//
// pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, _modulus: u64, _rng: &mut RNG) -> Vec<u64>{
//     (0..n).map(|_| 71).collect()
//     // rng.gen::<u64>()%modulus
// }
//
// pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
//     let mut ids = Vec::with_capacity(n);
//     for i in 0..n as u64{
//         let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
//         ids.push(v);
//     }
//     ids
// }

// Taken from:
// https://www.reddit.com/r/rust/comments/8tfyof/noob_question_pause/e177530?utm_source=share&utm_medium=web2x&context=3
fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

pub fn main(){
    // Get the root directory's location in order to find the configuration file
    // that's assumed to be in the match-compute-parallel folder
    // and in order to create the computations files and folders
    let mut path = env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.pop();
    path.pop();

    path.push("popsicle");
    path.push("examples");
    path.push("match-compute-parallel");
    path.push("configuration.txt");

    let absolute_path = path.clone().into_os_string().into_string().unwrap();
    let configuration = File::open(absolute_path).unwrap();
    let buffer = BufReader::new(configuration).lines();
    let mut parameters = HashMap::new();
    for line in buffer.enumerate(){
        let read_line =  line.1.unwrap();
        if !read_line.is_empty(){
            let line_split = read_line.split(": ").map(|item| item.to_string()).collect::<Vec<String>>();
            parameters.insert(line_split[0].clone(), line_split[1].clone());
        }
    }
    // The configuration file will have information about:
    // 1. The ip address of the server
    // 2. The duration needed for the client to sleep in order
    //    to wait for the server to finish before proceeding
    // 3. The number of threads between which the computation is being parallelized
    // 4. The size of a megabin that is given to a thread
    //    (each thread takes a bunch of megabins)
    // 5. The precision of the computation: the computation assumes that all numbers are naturals
    //    but one can get passed that if the range of values is not too big by multiplying by dropping
    //    dropping any decimal value passed the precision and multiplying by 10^precision. The final
    //    answer is readjusted and divided by 10^precision.
    // 6. The path of the files that contains the ids and payloads
    // 7. The schema of the ids and payloads in the csv files (i.e. the names of their columns)
    // 8. For testing purposes, the client also gets the location of the servers data files to
    //    test the computation in the open

    let address = parameters.get("address").unwrap().to_owned();
    let sleeptime = parameters.get("sleeptime").unwrap().parse::<u64>().unwrap();

    let nthread = parameters.get("nthread").unwrap().parse::<usize>().unwrap();
    let megasize = parameters.get("megasize").unwrap().parse::<usize>().unwrap();

    let precision = parameters.get("precision").unwrap().parse::<u32>().unwrap();


    let client_path = parameters.get("data_path_client").unwrap().to_owned();
    let schema_id = parameters.get("schema_client_id").unwrap().to_owned();
    let schema_payload = parameters.get("schema_client_payload").unwrap().to_owned();

    // The ids & payloads are read from the csv according to their schema (column names),
    // and turned into the computations representation
    let (ids_client, payloads_client) = parse_files(&schema_id, &schema_payload, &client_path);

    // Alternatively uncomment this section to randomly generate the inputs. Don't forget
    // to also uncomment the necessary includes and methods at the top
    // let mut rng = AesRng::new();
    // let ids_client = enum_ids(1<<20, 16);
    // let payloads_client = int_vec_block512(rand_u64_vec(1<<20, 10,&mut rng));

   // Wait for the server to be done
   let duration = Duration::from_secs(sleeptime);

   // Bucketize the data and split into megabins that are distributed among threads
   path.pop();
   path.push("client");
   prepare_files(&mut path, &address, nthread, megasize, &ids_client, &payloads_client);
   //
    thread::sleep(duration);

    // Each thread handles its own megabins and speaks to the appropriate other party thread
    // via a dedicated port. The partial results of this computation are garbled and
    // stored into appropriate files. They are handled later to produce the correct output.
    let mut handle = Vec::new();
    for i in 0..nthread {
        let mut path_thread = path.clone();
        let address_thread = address.clone();
       handle.push(thread::spawn(move || {
           client_thread(&mut path_thread, &address_thread, i);
       }));
   }
   //
   for thread in handle {
        let _ = thread.join(); // maybe consider handling errors propagated from the thread here
    }
   //

   // The partial results are joined and the output is produced
    thread::sleep(duration);
    let (_result_aggregate, _result_cardinality) = join_aggregates(&mut path, &address, nthread, precision).unwrap();


    // // test results
    //
    let server_path = parameters.get("data_path_server").unwrap().to_owned();
    let schema_id = parameters.get("schema_server_id").unwrap().to_owned();
    let schema_payload = parameters.get("schema_server_payload").unwrap().to_owned();

    let (ids_server, payloads_server) = parse_files(&schema_id, &schema_payload, &server_path);
    let (weighted_aggregate, cardinality) = test(&ids_client, &ids_server, &payloads_client, &payloads_server);

    let aggregate: f64 = weighted_aggregate as f64/ 10_u64.pow(precision) as f64;
    let output: f64 = aggregate / cardinality as f64;

    path.push("result_nonsecure.txt");
    let path_str = path.clone().into_os_string().into_string().unwrap();
    path.pop();

    let _ = File::create(path_str.clone()).unwrap();

    let mut output_write = "Aggregate in the clear: ".to_owned();
    output_write.push_str(&aggregate.to_string());
    output_write.push_str(&"\nCardinality in the clea: ".to_owned());
    output_write.push_str(&cardinality.to_string());
    output_write.push_str(&"\nAverage in the clear: ".to_owned());
    output_write.push_str(&output.to_string());


    write(path_str, output_write).expect("Unable to write file");

    println!("Experiments done !");
    pause();
}
