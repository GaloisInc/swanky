//#[path = "pprf/pprf.rs"]
pub mod pprf;

fn main(){
    let params = pprf::pprf::Params {
        lambda: 10,
        l: 10,
        p:5,
        r:3
    };
    let key_space:pprf::BitVec = pprf::BitVec::with_capacity(params.lambda as usize);
    println!("Key space = {:?}", key_space);
 

}