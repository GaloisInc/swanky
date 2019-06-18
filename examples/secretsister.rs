use clap::{App, Arg};
use popsicle::{MultiPartyReceiver, MultiPartySender};
use std::net::{TcpListener, TcpStream};
use itertools::Itertools;
use serde::{Deserialize};

#[allow(non_camel_case_types)]
#[derive(Debug, Deserialize)]
enum PartyConfig {
    sender {
        address: String,
        port: String,
    },
    receiver {
        address: String,
        port: String,
    }
}

fn main() {
    let matches = App::new("secretsister")
                          .version("1.0")
                          .author("Brent Carmer <bcarmer@galois.com>")
                          .about("Multi-Party IPV6 Address Private Set Intersection using KMPRT")
                          .arg(Arg::with_name("config")
                               .short("c")
                               .long("config")
                               .value_name("FILE")
                               .help("Yaml config file.")
                               .takes_value(true)
                               .default_value("secretsister.yaml"))
                          .arg(Arg::with_name("ID")
                               .help("Party id.")
                               .required(true))
                          .arg(Arg::with_name("INPUT")
                               .help("Sets the input file to use.")
                               .required(true))
                          .setting(clap::AppSettings::ColorAlways)
                          .get_matches();

    let config: Vec<PartyConfig> = serde_yaml::from_reader(&mut std::fs::File::open(matches.value_of("config").unwrap()).unwrap()).unwrap();

    println!("{:?}", config);
}
