use ff::*;
use rand::*;
#[derive(PrimeField)]
#[PrimeFieldModulus = "340282366920938463463374607431768211297"]
#[PrimeFieldGenerator = "5"]
pub struct Fp(pub FpRepr);

impl rand::distributions::Distribution<Fp> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Fp {
        Fp(FpRepr(rng.gen::<[u64; 3]>()))
    }
}
