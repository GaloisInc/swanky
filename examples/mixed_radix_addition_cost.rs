use fancy_garbling::informer::{Informer, InformerVal};
use fancy_garbling::*;
use itertools::Itertools;

fn main() {
    let n = 5;
    let ps = vec![3, 4, 7, 83];

    let mut b = Informer::new();
    let xs = (0..n).map(|_| InformerVal::new_bundle(&ps)).collect_vec();
    let z = b.mixed_radix_addition_msb_only(&xs).unwrap();
    b.output(&z).unwrap();
    b.print_info();
}
