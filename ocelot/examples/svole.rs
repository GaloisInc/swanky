use ocelot::svole::{Receiver, Sender};
use ocelot::svole::{LPN_EXTEND_MEDIUM, LPN_SETUP_MEDIUM};
use scuttlebutt::{
    field::{F40b, F2},
    AbstractChannel, AesRng,
};
use std::io::{Read, Write};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Instant,
};

fn get_trials() -> usize {
    if let Ok(n) = std::env::var("N") {
        n.parse().unwrap()
    } else {
        1
    }
}

struct OurTrackChannel<S: Read + Write> {
    stream_w: BufWriter<S>,
    stream_r: BufReader<S>,
    bytes_written: u64,
    bytes_read: u64,
}

impl<S: Read + Write> OurTrackChannel<S> {
    fn new(w: S, r: S) -> Self {
        OurTrackChannel {
            stream_w: BufWriter::new(w),
            stream_r: BufReader::new(r),
            bytes_written: 0,
            bytes_read: 0,
        }
    }

    fn clear(&mut self) {
        self.bytes_read = 0;
        self.bytes_written = 0;
    }

    fn kilobits_read(&self) -> f64 {
        ((self.bytes_read as f64) * 8.0) / 1000.0
    }
    fn kilobits_written(&self) -> f64 {
        ((self.bytes_written as f64) * 8.0) / 1000.0
    }
}

impl<S: Read + Write> AbstractChannel for OurTrackChannel<S> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream_w.write_all(bytes)?;
        self.bytes_written += bytes.len() as u64;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        self.bytes_read += bytes.len() as u64;
        self.stream_r.read_exact(bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream_w.flush()
    }

    fn clone(&self) -> Self {
        unimplemented!()
    }
}

type VSender = Sender<F40b>;
type VReceiver = Receiver<F40b>;

fn run() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        {
            let mut cpu_set = nix::sched::CpuSet::new();
            cpu_set.set(1).unwrap();
            nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
        }
        let mut rng = AesRng::new();
        let mut channel =
            OurTrackChannel::new(sender.try_clone().unwrap(), sender.try_clone().unwrap());
        let start = Instant::now();
        let mut vole =
            VSender::init(&mut channel, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap();
        println!("Send time (init): {:?}", start.elapsed());
        let start = Instant::now();
        let mut count = 0;
        let mut out: Vec<(F2, F40b)> = Vec::new();
        for _ in 0..get_trials() {
            vole.send(&mut channel, &mut rng, &mut out).unwrap();
            count += out.len();
            criterion::black_box(&out);
        }
        println!("[{}] Send time (extend): {:?}", count, start.elapsed());
        let start = Instant::now();
        vole.duplicate(&mut channel, &mut rng).unwrap();
        println!("Send time (duplicate): {:?}", start.elapsed());
    });
    #[cfg(target_os = "linux")]
    {
        let mut cpu_set = nix::sched::CpuSet::new();
        cpu_set.set(3).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
    }
    let mut rng = AesRng::new();
    let mut channel =
        OurTrackChannel::new(receiver.try_clone().unwrap(), receiver.try_clone().unwrap());
    let start = Instant::now();
    let mut vole =
        VReceiver::init(&mut channel, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap();
    println!("Receive time (init): {:?}", start.elapsed());
    println!(
        "Send communication (init): {:.2} Mbits",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (init): {:.2} Mbits",
        channel.kilobits_written() / 1000.0
    );
    channel.clear();
    let start = Instant::now();
    let mut count = 0;
    let mut out = Vec::new();
    for _ in 0..get_trials() {
        vole.receive::<_, F2>(&mut channel, &mut rng, &mut out)
            .unwrap();
        count += out.len();
        criterion::black_box(&out);
    }
    println!("[{}] Receive time (extend): {:?}", count, start.elapsed());
    println!(
        "Send communication (extend): {:.2} Mbits",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (extend): {:.2} Mbits",
        channel.kilobits_written() / 1000.0
    );
    channel.clear();
    let start = Instant::now();
    let _ = vole.duplicate::<_, F2>(&mut channel, &mut rng).unwrap();
    println!("Receive time (duplicate): {:?}", start.elapsed());
    println!(
        "Send communication (duplicate): {:.2} Mbits",
        channel.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (duplicate): {:.2} Mbits",
        channel.kilobits_written() / 1000.0
    );
    handle.join().unwrap();
}

fn main() {
    println!("\nField: F2_40 \n");
    run/*::<Gf40, Sender<Gf40>, Receiver<Gf40>>*/()
}
