//! Implementation of a random number generator based on fixed-key AES.

use crate::aes::Aes128;
use arrayref::array_mut_ref;

pub struct AesRng {
    aes: Aes128,
}

type Seed = [u8; 16];

impl AesRng {
    #[inline(always)]
    pub fn new(seed: Seed) -> Self {
        let aes = Aes128::new(&seed);
        AesRng { aes }
    }
    #[inline(always)]
    pub fn random(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len() % 16, 0);
        for (i, m) in bytes.chunks_mut(16).enumerate() {
            let data = (i as u128).to_le_bytes();
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), m.as_mut_ptr(), 16) };
            let c = self.aes.encrypt_u8(array_mut_ref![m, 0, 16]);
            unsafe { std::ptr::copy_nonoverlapping(c.as_ptr(), m.as_mut_ptr(), 16) };
        }
    }
}
