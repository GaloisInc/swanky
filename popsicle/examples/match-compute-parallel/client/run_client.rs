mod prepare_files_client;
mod client_thread;
mod join_aggregates_client;


use prepare_files_client::prepare_files;
use client_thread::client_thread;
use join_aggregates_client::join_aggregates;


use std::{
    env,
    sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT},
    thread,
    time,
};


pub fn main(){
    let args: Vec<String> = env::args().collect();
    let nthread = args[1].parse::<usize>().unwrap();
    let duration = time::Duration::from_secs(5);


    prepare_files();

    thread::sleep(duration);

    let mut handle = Vec::new();
    for i in 0..nthread {
       handle.push(thread::spawn(move || {
           client_thread(i);
       }));
   }

   for thread in handle {
        let _ = thread.join(); // maybe consider handling errors propagated from the thread here
    }

    thread::sleep(duration);
    join_aggregates(nthread);
}
