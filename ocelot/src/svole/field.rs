use ff::*;
use rand::*;

#[derive(PrimeField)]
#[PrimeFieldModulus = "340282366920938463463374607431768211297"]
#[PrimeFieldGenerator = "5"]
pub struct Fp(pub FpRepr);

impl Fp {}

impl rand::distributions::Distribution<Fp> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Fp {
        Fp(FpRepr(rng.gen::<[u64; 3]>()))
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

/*impl From<Fp> for [u8; 24] {
    #[inline]
    fn from(m: Fp) -> [u8; 24] {
        unsafe { *(&((m.0).0) as *const _ as *const [u8; 24]) }
    }
}*/

impl From<Fp> for [u8; 16] {
    #[inline]
    fn from(m: Fp) -> [u8; 16] {
        unsafe { *(&((m.0).0) as *const _ as *const [u8; 16]) }
    }
}

impl From<[u64; 3]> for Fp {
    #[inline]
    fn from(m: [u64; 3]) -> Self {
        Fp(FpRepr(m))
    }
}
impl From<[u64; 2]> for Fp {
    #[inline]
    fn from(m: [u64; 2]) -> Self {
        let m_: [u64; 3] = [m[0], m[1], 0u64];
        Fp(FpRepr(m_))
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

/*

/// Write a `Fp` to the channel.
   //#[cfg(feature = "ff")]
   #[inline(always)]
   fn write_fp(&mut self, s: Fp) -> Result<()> {
       for i in 0..((s.0).0).len() {
           self.write_u64(((s.0).0)[i])?;
       }
       Ok(())
   }

   /// Read a `Fp` from the channel.
   //#[cfg(feature = "ff")]
   #[inline(always)]
   fn read_fp(&mut self) -> Result<Fp> {
       let mut data = [0u64; 3];
       for item in &mut data {
           *item = self.read_u64()?;
       }
       Ok(Fp(FpRepr(data)))
   }
   */
