mod prepare_files_server;
mod server_thread;
mod join_aggregates_server;


use prepare_files_server::prepare_files;
use server_thread::server_thread;
use join_aggregates_server::join_aggregates;


use std::{
    env,
    sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT},
    thread,
    time::Duration,
};


pub fn main(){
    let args: Vec<String> = env::args().collect();
    let nthread = args[1].parse::<usize>().unwrap();


    prepare_files();

    let mut handle = Vec::new();
    for i in 0..nthread {
       handle.push(thread::spawn(move || {
           server_thread(i);
       }));
   }
   for thread in handle {
        let _ = thread.join(); // maybe consider handling errors propagated from the thread here
    }

    join_aggregates(nthread);
}
