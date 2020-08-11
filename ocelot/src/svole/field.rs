use ff::*;
use rand::*;
use scuttlebutt::Block;

#[derive(PrimeField)]
//#[PrimeFieldModulus = "340282366920938463463374607431768211297"]
#[PrimeFieldModulus = "35742549198872617291353508656626642567"]
#[PrimeFieldGenerator = "5"]
pub struct Fp(pub FpRepr);

impl FpRepr {
    #[inline]
    pub fn to_u128(&self) -> u128 {
        let arr: [u64; 2] = self.0;
        u128::from((arr[1] as u128) << 64 | arr[0] as u128)
    }
}

impl Fp {
    #[inline]
    pub fn to_block(&self) -> Block {
        Block::from(self.0.to_u128())
    }
}

impl rand::distributions::Distribution<Fp> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Fp {
        Fp(FpRepr(rng.gen::<[u64; 2]>()))
    }
}

impl AsRef<[u8]> for Fp {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { &*(self as *const Fp as *const [u8; 16]) }
    }
}

impl AsMut<[u8]> for Fp {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *(self as *mut Fp as *mut [u8; 16]) }
    }
}

impl From<Fp> for [u8; 16] {
    #[inline]
    fn from(m: Fp) -> [u8; 16] {
        unsafe { *(&((m.0).0) as *const _ as *const [u8; 16]) }
    }
}

impl From<[u64; 2]> for Fp {
    #[inline]
    fn from(m: [u64; 2]) -> Self {
        Fp(FpRepr(m))
    }
}

impl From<Block> for Fp {
    #[inline]
    fn from(m: Block) -> Self {
        PrimeField::from_str(&u128::from(m).to_string()).unwrap()
    }
}

#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
impl Serialize for Fp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&unsafe { std::mem::transmute::<[u64; 3], [u8; 24]>(self.0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_block() {
        let x = rand::random::<Fp>();
        let y = u128::from(x.to_block());
        assert_eq!(x, PrimeField::from_str(&y.to_string()).unwrap());
    }

    #[test]
    fn to_u128() {
        let a = rand::random::<u128>();
        let x: Fp = PrimeField::from_str(&a.to_string()).unwrap();
        assert_eq!(a, (x.0).to_u128());
    }

    #[test]
    fn from_block() {
        let x = rand::random::<Block>();
        let y = Fp::from(x);
        assert_eq!(x, y.to_block());
    }
}
