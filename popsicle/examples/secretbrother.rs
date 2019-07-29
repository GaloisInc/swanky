use clap::{App, SubCommand};
use pbr::PbIter;
use popsicle::psz;
use rand::Rng;
use rustyline::Editor;
use scuttlebutt::{AbstractChannel, AesRng, Block, TrackChannel};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    net::{TcpListener, TcpStream},
};
use openssl::sha::sha256;

fn main() {
    let matches = App::new("secretborther")
        .version("1.0")
        .author("Brent Carmer <bcarmer@galois.com>")
        .about("Two-party private set intersection with payloads using PSZ")
        .subcommand(SubCommand::with_name("sender").about("Send payloads to the receiver"))
        .subcommand(SubCommand::with_name("receiver").about("Receive payloads from the sender"))
        .setting(clap::AppSettings::ColorAlways)
        .get_matches();

    let mut rl = Editor::<()>::new();

    let mut rng = AesRng::new();

    match matches.subcommand_name() {
        Some("sender") => sender(&mut rl, &mut rng),
        Some("receiver") => receiver(&mut rl, &mut rng),
        Some(_) => unreachable!(),
        None => println!("Error: PSI party mode required (sender or receiver). Try --help."),
    }
}

fn sender(rl: &mut Editor<()>, rng: &mut AesRng) {
    let start = std::time::SystemTime::now();
    // let addr = rl.readline("Address? >> ").unwrap();
    // let port = rl.readline("Port? >> ").unwrap();
    let addr = "localhost";
    let port = "12345";

    let stream = loop {
        match TcpStream::connect(&format!("{}:{}", addr, port)) {
            Ok(stream) => break stream,
            _ => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    };

    let mut channel = TrackChannel::new(
        BufReader::new(stream.try_clone().unwrap()),
        BufWriter::new(stream),
    );
    println!("Connected to {}:{}.", addr, port);

    println!("Initializing PSI sender.");
    let mut sender = psz::Sender::init(&mut channel, rng).unwrap();

    // let input_filename = rl.readline("Input csv file? >> ").unwrap();
    let input_filename = "sender.csv";
    println!("Reading input CSV file.");
    let (inputs, payloads) = read_inputs_and_payloads(&input_filename);

    println!("Performing private set intersection.");
    let payload_keys = sender.send_payloads(&inputs, &mut channel, rng).unwrap();

    let cardinality = channel.read_usize().unwrap();

    let mut bytes = [0; 1];
    loop {
        print!(
            "Receiver reports cardinality {}. Accept? [yn] ",
            cardinality
        );
        std::io::stdout().flush().unwrap();

        // std::io::stdin().lock().read_exact(&mut bytes).unwrap();
        bytes[0] = b'y';
        println!("");

        match bytes[0] {
            b'y' => {
                channel.write_bool(true).unwrap();
                println!("Cardinality approved.");
                break;
            }
            b'n' => {
                channel.write_bool(false).unwrap();
                println!("Sender disapproved cardinality. Exiting.");
                std::process::exit(0);
            }
            c => {
                println!("Unknown input \"{}\"", c);
            }
        }
    }
    channel.flush().unwrap();
    println!("PSI took {} seconds.", start.elapsed().unwrap().as_secs());

    println!("Sending encrypted payloads.");

    channel.write_usize(inputs.len()).unwrap();
    channel.write_usize(payloads[0].len()).unwrap();
    assert!(payloads.iter().all(|p| p.len() == payloads[0].len()));

    for ((input, payload), payload_key) in PbIter::new(inputs.iter().zip(payloads.iter()).zip(payload_keys.iter())) {
        let tag: [u8;32] = sha256(input);
        let (iv, encrypted_payload) = encrypt(payload_key, payload, rng);
        channel.write_bytes(&tag).unwrap();
        channel.write_block(&iv).unwrap();
        channel.write_bytes(&encrypted_payload).unwrap();
        channel.flush().unwrap();
    }

    println!("Total time: {:.2} seconds", start.elapsed().unwrap().as_secs());
    println!("Total communication: {:.2} megabytes", channel.total_kilobytes() / 1024.0);
}

fn receiver(rl: &mut Editor<()>, rng: &mut AesRng) {
    let start = std::time::SystemTime::now();

    // let port = rl.readline("Port? >> ").unwrap();
    let port = "12345";

    println!("Waiting for connection from sender.");
    let (stream, addr) = TcpListener::bind(format!("localhost:{}", port))
        .unwrap()
        .accept()
        .unwrap();
    let mut channel = TrackChannel::new(
        BufReader::new(stream.try_clone().unwrap()),
        BufWriter::new(stream),
    );
    println!("Connected to {}.", addr);

    println!("Initializing PSI receiver.");
    let mut receiver = psz::Receiver::init(&mut channel, rng).unwrap();

    // let input_filename = rl.readline("Input CSV file? >> ").unwrap();
    // let output_filename = rl.readline("Output CSV file? >> ").unwrap();
    let input_filename = "receiver.csv";
    let output_filename = "output.csv";
    println!("Reading input CSV file.");
    let inputs = read_inputs(&input_filename);

    println!("Performing private set intersection.");
    let payload_keys: HashMap<_,_> = receiver
        .receive_payloads(&inputs, &mut channel, rng)
        .unwrap()
        .into_iter()
        .map(|(item, key) | {
            let tag = sha256(&item).to_vec();
            (tag, (item, key))
        }).collect();
    println!("Intersection size: {}.", payload_keys.len());
    println!("PSI took {} seconds.", start.elapsed().unwrap().as_secs());

    println!("Sending cardinality to Sender.");
    channel.write_usize(payload_keys.len()).unwrap();
    channel.flush().unwrap();

    let approved = channel.read_bool().unwrap();
    if approved {
        println!("Sender approved cardinality.");
    } else {
        println!("Sender disapproved cardinality. Exiting.");
        std::process::exit(0);
    }

    println!("Receiving encrypted payloads.");

    let mut output_file = std::fs::File::create(&output_filename).unwrap();

    let sender_set_size = channel.read_usize().unwrap();
    let payload_len = channel.read_usize().unwrap();

    for _ in PbIter::new(0..sender_set_size) {
        let tag = channel.read_vec(32).unwrap();
        let iv = channel.read_block().unwrap();
        let encrypted_payload = channel.read_vec(payload_len).unwrap();
        if let Some((item, key)) = payload_keys.get(&tag) {
            let payload = decrypt(&key, &iv, &encrypted_payload);
            let s = format_output_line(&item, &payload);
            writeln!(output_file, "{}", s).unwrap();
        }
    }

    println!("Wrote payloads to {}.", output_filename);
    println!("Total time: {:.2} seconds", start.elapsed().unwrap().as_secs());
    println!("Total communication: {:.2} megabytes", channel.total_kilobytes() / 1024.0);
}

fn read_inputs(filename: &str) -> Vec<Vec<u8>> {
    BufReader::new(std::fs::File::open(filename).unwrap())
        .lines()
        .map(|line| {
            let val = line.unwrap();
            assert_eq!(
                val.len(),
                11,
                "ssn should be of the form \"123-45-6789\", got {}",
                val
            );
            process_ssn(&val)
        })
        .collect()
}

fn read_inputs_and_payloads(
    filename: &str,
) -> (
    Vec<Vec<u8>>, // inputs
    Vec<Vec<u8>>, // payloads
) {
    let mut inputs = Vec::new();
    let mut payloads = Vec::new();
    for line in BufReader::new(std::fs::File::open(filename).unwrap()).lines() {
        let vals: Vec<String> = line
            .unwrap()
            .split(",")
            .map(|s| s.trim().to_string())
            .collect();
        assert_eq!(vals.len(), 5);
        assert_eq!(
            vals[0].len(),
            11,
            "ssn should be of the form \"123-45-6789\", got {}",
            vals[0]
        );
        inputs.push(process_ssn(&vals[0]));
        let mut payload = f64_to_bytes(vals[1].parse().unwrap());
        payload.extend(f64_to_bytes(vals[2].parse().unwrap()));
        payload.extend(f64_to_bytes(vals[3].parse().unwrap()));
        let mut p4 = vals[4].as_bytes().to_vec();
        assert!(p4.len() <= 24, "final payload should be at most 24 bytes");
        p4.resize(24, 0); // pad with 0s for final payloads less than 24 bytes.
        payload.extend(p4);
        payloads.push(payload);
    }
    (inputs, payloads)
}

fn encrypt(key: &Block, data: &[u8], rng: &mut AesRng) -> (Block, Vec<u8>) {
    let iv = rng.gen::<Block>();
    let ct = openssl::symm::encrypt(
        openssl::symm::Cipher::aes_128_ctr(),
        key.as_ref(),
        Some(iv.as_ref()),
        data,
    )
    .unwrap();
    (iv, ct)
}

fn decrypt(key: &Block, iv: &Block, data: &[u8]) -> Vec<u8> {
    openssl::symm::decrypt(
        openssl::symm::Cipher::aes_128_ctr(),
        key.as_ref(),
        Some(iv.as_ref()),
        data,
    )
    .unwrap()
}

fn format_output_line(input: &[u8], payload: &[u8]) -> String {
    let tag = format_ssn(input);
    let p1 = bytes_to_f64(&payload[0..8]);
    let p2 = bytes_to_f64(&payload[8..16]);
    let p3 = bytes_to_f64(&payload[16..24]);
    let p4 = std::str::from_utf8(&payload[24..]).unwrap();
    format!("{}, {}, {}, {}, {}", tag, p1, p2, p3, p4)
}

fn f64_to_bytes(val: f64) -> Vec<u8> {
    let input_array: [u8; 8] = unsafe { std::mem::transmute(val) };
    input_array.to_vec()
}

fn bytes_to_f64(bytes: &[u8]) -> f64 {
    assert_eq!(bytes.len(), 8);
    let mut bytes_array = [0; 8];
    for (x, y) in bytes.iter().zip(bytes_array.iter_mut()) {
        *y = *x;
    }
    unsafe { std::mem::transmute(bytes_array) }
}

fn process_ssn(ssn: &str) -> Vec<u8> {
    // parse it as a u64, then output the bytes of it
    let mut no_formatting = String::new();
    for c in ssn.chars() {
        match c {
            '-' => (),
            _ => no_formatting.push(c),
        }
    }
    let val = no_formatting.parse::<u64>().unwrap();
    let bs: [u8;8] = unsafe { std::mem::transmute(val) };
    bs.to_vec()
}

fn format_ssn(bs: &[u8]) -> String {
    let mut bs_arr = [0; 8];
    for (from, to) in bs.iter().zip(bs_arr.iter_mut()) {
        *to = *from;
    }
    let val: u64 = unsafe { std::mem::transmute(bs_arr) };
    let mut s = format!("{:09}", val);
    s.insert(3, '-');
    s.insert(6, '-');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_conversion() {
        for _ in 0..1024 {
            // test i64 conversion
            let x = random();
            let bs = f64_to_bytes(x);
            assert_eq!(x, bytes_to_f64(&bs));
        }
    }

    #[test]
    fn test_encryption() {
        for _ in 0..1024 {
            let mut rng = AesRng::new();
            let bs = (0..128).map(|_| rng.gen()).collect::<Vec<_>>();
            let key = rng.gen();
            let (iv, ct) = encrypt(&key, &bs, &mut rng);
            assert_eq!(decrypt(&key, &iv, &ct), bs);
        }
    }

    #[test]
    fn test_ssn_processing() {
        for _ in 0..1024 {
            let mut rng = AesRng::new();
            let mut tag = String::new();
            let chars = (b'0' ..= b'9').map(char::from).collect::<Vec<char>>();
            for _ in 0..3 {
                let i = rng.gen::<usize>() % 10;
                tag.push(chars[i]);
            }
            tag.push('-');
            for _ in 0..2 {
                let i = rng.gen::<usize>() % 10;
                tag.push(chars[i]);
            }
            tag.push('-');
            for _ in 0..4 {
                let i = rng.gen::<usize>() % 10;
                tag.push(chars[i]);
            }
            assert_eq!(format_ssn(&process_ssn(&tag)), tag);
        }
    }
}
