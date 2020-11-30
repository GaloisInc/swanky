use std::{
    fs::{File},
    io::{BufRead, BufReader},
};

use scuttlebutt::{Block512};


pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..8{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn parse_files(id_schema: &str, payload_schema: &str, path: &str) -> (Vec<Vec<u8>>, Vec<Block512>){

     let data = File::open(path).unwrap();

     let buffer = BufReader::new(data).lines();

     let mut ids = Vec::new();
     let mut payloads = Vec::new();
     let mut id_position = 0;
     let mut payload_position = 0;

     let mut cnt = 0;
     for line in buffer.enumerate(){
         let line_split = line.1.unwrap().split(",").map(|item| item.to_string()).collect::<Vec<String>>();
         if cnt == 0 {
             id_position = line_split.iter().position(|x| x == id_schema).unwrap();
             payload_position = line_split.iter().position(|x| x == payload_schema).unwrap();
             cnt = cnt+1;
         } else{
            ids.push(line_split[id_position].parse::<u64>().unwrap().to_le_bytes().to_vec());
            payloads.push(line_split[payload_position].parse::<u64>().unwrap());
         }
     }
    (ids, int_vec_block512(payloads))
}
