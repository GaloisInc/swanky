//#[path = "pprf/pprf.rs"]
pub mod pprf;
extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::mem;
use pprf::pprf::Params;

fn main(){
    
    let ks:pprf::BitVec = pprf::BitVec::with_capacity(Params::LAMBDA as usize);
    let i: u128 = 12345;
    let mut bs = [0u8; mem::size_of::<u128>()];
    bs.as_mut()
        .write_u128::<LittleEndian>(i)
        .expect("Unable to write");

    for i in &bs {
        println!("{:b}", i);
    }
 

}