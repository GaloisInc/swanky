use fancy_garbling::{depth_informer::DepthInformer};
use fancy_garbling::{FancyInput, BinaryGadgets};

fn main() {
    let mut i = DepthInformer::new();
    let x = i.bin_encode(42, 64).unwrap();
    let y = i.bin_cmul(&x, 123, 64).unwrap();
    i.bin_output(&y).unwrap();
    println!("{}", i);
}
