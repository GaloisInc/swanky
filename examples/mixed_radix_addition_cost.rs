use fancy_garbling::informer::Informer;
use fancy_garbling::*;

fn main() {
    let n = 5;
    let ps = vec![3, 4, 7, 83];

    let b = Informer::new();
    let xs = b.garbler_input_bundles(None, &ps, n, None).unwrap();
    let z = b.mixed_radix_addition_msb_only(None, &xs).unwrap();
    b.output(None, &z).unwrap();
    b.print_info();
}
