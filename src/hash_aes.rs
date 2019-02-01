//! Implementation of a correlation-robust hash function based on fixed-key AES
//! (cf. https://eprint.iacr.org/2019/074, §7.2).
//!
//! The scheme itself is simple: `H(x) = π(x) ⊕ x`, where `π = AES(K, ·)` for
//! some fixed key `K`. The value `x` here must be of type `[u8; 16]`; namely, a
//! 128-bit value.
//!
//! It is important to note that this scheme only provides
//! correlation-robustness, and is thus *not* secure for use in settings where a
//! stronger assumption is needed, such as in maliciously-secure OT extension
//! protocols.

use crate::aes::Aes128;
use crate::utils;
use arrayref::array_ref;

pub struct AesHash {
    aes: Aes128,
}

impl AesHash {
    #[inline(always)]
    pub fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key);
        AesHash { aes }
    }
    #[inline(always)]
    pub fn hash(&self, _i: usize, x: &[u8]) -> Vec<u8> {
        let y = self.aes.encrypt_u8(array_ref![x, 0, 16]);
        utils::xor(&x, &y)
    }
}
