//#[path = "pprf/pprf.rs"]
pub mod pprf;
extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::mem;

fn main(){
    let params = pprf::pprf::Params {
        lambda: 10,
        l: 10,
        p:5,
        r:3
    };
    let ks:pprf::BitVec = pprf::BitVec::with_capacity(params.lambda as usize);
    let i: u128 = 12345;
    let mut bs = [0u8; mem::size_of::<u128>()];
    bs.as_mut()
        .write_u128::<LittleEndian>(i)
        .expect("Unable to write");

    for i in &bs {
        println!("{:b}", i);
    }
 

}