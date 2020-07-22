
use ff::*;
use rand::*;
#[derive(PrimeField)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
pub struct Fp(pub FpRepr);



impl rand::distributions::Distribution<Fp> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Fp {
        Fp ( FpRepr (rng.gen::<[u64;4]>()))
    }
}

