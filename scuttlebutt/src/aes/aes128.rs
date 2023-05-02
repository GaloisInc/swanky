use crate::Block;
use vectoreyes::{
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
    Aes128EncryptOnly, AesBlockCipher, U8x16,
};

/// AES-128, encryption only.
#[derive(Clone)]
pub struct Aes128(pub Aes128EncryptOnly);

impl Aes128 {
    /// Create a new `Aes128` object, using `key` as the AES key.
    #[inline]
    pub fn new(key: Block) -> Self {
        Aes128(Aes128EncryptOnly::new_with_key(key.0.into()))
    }
    /// Encrypt a block, outputting the ciphertext.
    #[inline(always)]
    pub fn encrypt(&self, m: Block) -> Block {
        Block(self.0.encrypt(m.0.into()).into())
    }
    /// Encrypt up to 32 blocks at a time, outputting the ciphertexts.
    #[inline(always)]
    pub fn encrypt_blocks<const Q: usize>(&self, blocks: [Block; Q]) -> [Block; Q]
    where
        ArrayUnrolledOps: UnrollableArraySize<Q>,
    {
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

/// Fixed-key AES-128.
pub const FIXED_KEY_AES128: Aes128 = Aes128(Aes128EncryptOnly::FIXED_KEY);

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_aes_128() {
        let key = Block::from(0x3C4FCF098815F7ABA6D2AE2816157E2B);
        let pt = Block::from(0x2A179373117E3DE9969F402EE2BEC16B);
        let cipher = Aes128::new(key);
        let ct = cipher.encrypt(pt);
        assert_eq!(ct, Block::from(0x97EF6624F3CA9EA860367A0DB47BD73A));
    }
}
