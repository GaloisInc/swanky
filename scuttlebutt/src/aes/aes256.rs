use crate::Block;
use vectoreyes::{array_utils::ArrayUnrolledExt, Aes256EncryptOnly, AesBlockCipher, U8x16, U8x32};

/// AES-256, encryption only.
#[derive(Clone)]
pub struct Aes256(Aes256EncryptOnly);

impl Aes256 {
    /// Create a new `Aes256` object, using `key` as the AES key.
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256(Aes256EncryptOnly::new_with_key(U8x32::from(*key)))
    }

    /// Encrypt a block, outputting the ciphertext.
    #[inline(always)]
    pub fn encrypt(&self, m: Block) -> Block {
        Block(self.0.encrypt(m.0.into()).into())
    }
    /// Encrypt eight blocks at a time, outputting the ciphertexts.
    #[inline(always)]
    pub fn encrypt8(&self, blocks: [Block; 8]) -> [Block; 8] {
        self.0
            .encrypt_many(blocks.array_map(
                #[inline(always)]
                |block| U8x16::from(block),
            ))
            .array_map(
                #[inline(always)]
                |block| Block::from(block),
            )
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_aes_256() {
        let k1: u128 = 0x81777D85F0AE732BBE71CA1510EB3D60;
        let k2: u128 = 0xF4DF1409A310982DD708613B072C351F;
        let key = [k1, k2];
        let key = bytemuck::cast(key);
        let cipher = Aes256::new(&key);
        let pt = Block::from(0x2A179373117E3DE9969F402EE2BEC16B);
        let ct = cipher.encrypt(pt);
        assert_eq!(ct, Block::from(0xF881B13D7E5A4B063CA0D2B5BDD1EEF3));
    }
}
