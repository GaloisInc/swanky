//#[path = "pprf/pprf.rs"]
//pub mod pprf;

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::mem;
//use pprf::pprf::Params;
use ocelot::field::*;


fn main(){
    
    //let ks:pprf::BitVec = pprf::BitVec::with_capacity(Params::LAMBDA as usize);
    let i: u128 = 12345;
    let mut u:Vec<bool> = Vec::new();
    u.push(true);
    u.push(false);
    let mut bs = [0u8; mem::size_of::<u128>()];
    println!("{}", u[0]);
    bs.as_mut()
        .write_u128::<LittleEndian>(i)
        .expect("Unable to write");

    for i in &bs {
        println!("{:b}", i);
    }
    let xp:Fp = Fp (FpRepr([3, 4, 5,6]));

        for i in 0..4{
            println!("{}", ((xp.0).0)[i]);
            //println!("{:?}", (xp.0).);
        }
      
    }

