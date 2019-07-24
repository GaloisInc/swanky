use clap::{App, SubCommand};
use pbr::PbIter;
use popsicle::psz;
use rand::Rng;
use rustyline::Editor;
use scuttlebutt::{AbstractChannel, AesRng, Block, TrackChannel};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};

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
    let addr = rl.readline("Address? >> ").unwrap();
    let port = rl.readline("Port? >> ").unwrap();

    let stream = TcpStream::connect(&format!("{}:{}", addr, port)).unwrap();
    let mut channel = TrackChannel::new(
        BufReader::new(stream.try_clone().unwrap()),
        BufWriter::new(stream),
    );
    println!("Connected to {}:{}.", addr, port);

    println!("Initializing PSI sender.");
    let mut sender = psz::Sender::init(&mut channel, rng).unwrap();

    let input_filename = rl.readline("Input csv file? >> ").unwrap();
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

        std::io::stdin().lock().read_exact(&mut bytes).unwrap();
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

    println!("Sending encrypted payloads.");

    // send payload length
    channel.write_usize(payloads[0].len()).unwrap();

    for (payload, payload_key) in PbIter::new(payloads.iter().zip(payload_keys.iter())) {
        let (iv, encrypted_payload) = encrypt(payload_key, payload, rng);
        channel.write_block(&iv).unwrap();
        channel.write_bytes(&encrypted_payload).unwrap();
    }
}

fn receiver(rl: &mut Editor<()>, rng: &mut AesRng) {
    let port = rl.readline("Port? >> ").unwrap();

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

    let input_filename = rl.readline("Input CSV file? >> ").unwrap();
    let output_filename = rl.readline("Output CSV file? >> ").unwrap();
    println!("Reading input CSV file.");
    let inputs = read_inputs(&input_filename);

    println!("Performing private set intersection.");
    let payload_keys: HashMap<Vec<u8>, Block> = receiver
        .receive_payloads(&inputs, &mut channel, rng)
        .unwrap()
        .into_iter()
        .collect();
    println!("Intersection size: {}.", payload_keys.len());

    println!("Sending cardinality to Sender.");
    channel.write_usize(payload_keys.len()).unwrap();

    let approved = channel.read_bool().unwrap();
    if approved {
        println!("Sender approved cardinality.");
    } else {
        println!("Sender disapproved cardinality. Exiting.");
        std::process::exit(0);
    }

    println!("Receiving encrypted payloads.");

    let mut output_file = std::fs::File::create(&output_filename).unwrap();
    let payload_len = channel.read_usize().unwrap();

    for input in PbIter::new(inputs.iter()) {
        let iv = channel.read_block().unwrap();
        let encrypted_payload = channel.read_vec(payload_len).unwrap();
        if let Some(key) = payload_keys.get(input) {
            let payload = decrypt(&key, &iv, &encrypted_payload);
            write_output_line(&mut output_file, &input, &payload);
        }
    }

    println!("Wrote payloads to {}.", output_filename);
}

fn read_inputs(filename: &str) -> Vec<Vec<u8>> {
    BufReader::new(std::fs::File::open(filename).unwrap())
        .lines()
        .map(|line| {
            let val = line.unwrap().parse().unwrap();
            u64_to_bytes(val)
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
        assert_eq!(vals.len(), 3);
        inputs.push(u64_to_bytes(vals[0].parse().unwrap()));
        let mut payload = i64_to_bytes(vals[1].parse().unwrap());
        payload.extend(i64_to_bytes(vals[2].parse().unwrap()));
        payloads.push(payload);
    }
    (inputs, payloads)
}

fn encrypt(key: &Block, data: &[u8], rng: &mut AesRng) -> (Block, Vec<u8>) {
    let iv = rng.gen::<Block>();
    let ct = openssl::symm::encrypt(
        openssl::symm::Cipher::aes_128_cbc(),
        key.as_ref(),
        Some(iv.as_ref()),
        data,
    )
    .unwrap();
    (iv, ct)
}

fn decrypt(key: &Block, iv: &Block, data: &[u8]) -> Vec<u8> {
    openssl::symm::decrypt(
        openssl::symm::Cipher::aes_128_cbc(),
        key.as_ref(),
        Some(iv.as_ref()),
        data,
    )
    .unwrap()
}

fn write_output_line(output_file: &mut std::fs::File, input: &[u8], payload: &[u8]) {
    let val = bytes_to_u64(input);
    let p1 = bytes_to_i64(&payload[0..8]);
    let p2 = bytes_to_i64(&payload[8..]);
    writeln!(output_file, "{}, {}, {}", val, p1, p2).unwrap();
}

fn u64_to_bytes(val: u64) -> Vec<u8> {
    let input_array: [u8; 8] = unsafe { std::mem::transmute(val) };
    input_array.to_vec()
}

fn i64_to_bytes(val: i64) -> Vec<u8> {
    let input_array: [u8; 8] = unsafe { std::mem::transmute(val) };
    input_array.to_vec()
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    assert_eq!(bytes.len(), 8);
    let mut bytes_array = [0; 8];
    for (x, y) in bytes.iter().zip(bytes_array.iter_mut()) {
        *y = *x;
    }
    unsafe { std::mem::transmute(bytes_array) }
}

fn bytes_to_i64(bytes: &[u8]) -> i64 {
    assert_eq!(bytes.len(), 8);
    let mut bytes_array = [0; 8];
    for (x, y) in bytes.iter().zip(bytes_array.iter_mut()) {
        *y = *x;
    }
    unsafe { std::mem::transmute(bytes_array) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_conversion() {
        for _ in 0..1024 {
            // test u64 conversion
            let x = random();
            let bs = u64_to_bytes(x);
            assert_eq!(x, bytes_to_u64(&bs));

            // test i64 conversion
            let x = random();
            let bs = i64_to_bytes(x);
            assert_eq!(x, bytes_to_i64(&bs));
        }
    }

    #[test]
    fn test_encryption() {
        for _ in 0..1024 {
            let mut rng = AesRng::new();
            let x = rng.gen();
            let bs = u64_to_bytes(x);
            let key = rng.gen();
            let (iv, ct) = encrypt(&key, &bs, &mut rng);
            assert_eq!(decrypt(&key, &iv, &ct), bs);
        }
    }
}
