use fancy_garbling::{error::InformerError, informer::{Informer, InformerVal}};
use fancy_garbling::*;

fn main() {
    let n = 5;
    let ps = vec![3, 4, 7, 83];

    let mut b = Informer::new();
    let xs = (0..n).map(|_| b.receive_bundle(&ps)).collect::<Result<Vec<Bundle<InformerVal>>, InformerError>>().unwrap();
    let z = b.mixed_radix_addition_msb_only(&xs).unwrap();
    b.output(&z).unwrap();
    b.print_info();
}
