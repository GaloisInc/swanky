use fancy_garbling::*;
use fancy_garbling::informer::Informer;

fn main() {
    let n = 5;
    let ps = vec![3,4,7,83];

    let b = Informer::new();
    let xs = b.garbler_input_bundles(None, &ps, n, None);
    let z = b.mixed_radix_addition_msb_only(None, &xs);
    b.output(None, &z);
    b.print_info();
}
