mod prepare_files_client;
mod client_thread;
mod join_aggregates_client;


use prepare_files_client::prepare_files;
use client_thread::client_thread;
use join_aggregates_client::join_aggregates;


use std::{
    env,
    fs::{File},
    io::{BufRead, BufReader},
    collections::HashMap,
    time::{Duration},
    thread,
};

pub fn main(){
    let mut absolute_path = env::current_exe().unwrap();
    absolute_path.pop();
    absolute_path.pop();
    absolute_path.pop();
    absolute_path.pop();

    let mut absolute_path = absolute_path.into_os_string().into_string().unwrap();//
    absolute_path.push_str("/popsicle/examples/match-compute-parallel/");
    let configuration = File::open(format!("{}{}", absolute_path, "configuration.txt")).unwrap();

    let buffer = BufReader::new(configuration).lines();

    let mut parameters = HashMap::new();
    for line in buffer.enumerate(){
        let line_split = line.1.unwrap().split(": ").map(|item| item.to_string()).collect::<Vec<String>>();
        parameters.insert(line_split[0].clone(), line_split[1].clone());
    }
    let address = parameters.get("address").unwrap().to_owned();
    let nthread = parameters.get("nthread").unwrap().parse::<usize>().unwrap();
    let setsize = parameters.get("setsize").unwrap().parse::<usize>().unwrap();
    let itemsize = parameters.get("itemsize").unwrap().parse::<usize>().unwrap();
    let megasize = parameters.get("megasize").unwrap().parse::<usize>().unwrap();
    let sleeptime = parameters.get("sleeptime").unwrap().parse::<u64>().unwrap();

    let duration = Duration::from_secs(sleeptime);

    absolute_path.push_str("client/");
    prepare_files(&absolute_path, &address, nthread, setsize, itemsize, megasize);

    thread::sleep(duration);

    let mut handle = Vec::new();
    for i in 0..nthread {
        let absolute_path_thread = absolute_path.clone();
        let address_thread = address.clone();
       handle.push(thread::spawn(move || {
           client_thread(&absolute_path_thread, &address_thread, i);
       }));
   }

   for thread in handle {
        let _ = thread.join(); // maybe consider handling errors propagated from the thread here
    }

    thread::sleep(duration);
    join_aggregates(&absolute_path, &address, nthread);
}
