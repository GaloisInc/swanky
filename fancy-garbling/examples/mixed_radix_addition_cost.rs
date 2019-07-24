use fancy_garbling::*;
use fancy_garbling::{
    dummy::{Dummy, DummyVal},
    error::DummyError,
    informer::Informer,
};

fn main() {
    let n = 5;
    let ps = vec![3, 4, 7, 83];

    let mut b = Informer::new(Dummy::new());
    let xs = (0..n)
        .map(|_| b.receive_bundle(&ps))
        .collect::<Result<Vec<Bundle<DummyVal>>, DummyError>>()
        .unwrap();
    let z = b.mixed_radix_addition_msb_only(&xs).unwrap();
    b.output(&z).unwrap();
    println!("{}", b.stats());
}
