use aesni::block_cipher_trait::generic_array::GenericArray;
use aesni::block_cipher_trait::BlockCipher;
use aesni::Aes128;

pub struct AesRng {
    aes: Aes128,
}

type Seed = [u8; 16];

impl AesRng {
    pub fn new(seed: Seed) -> Self {
        let k = GenericArray::from_slice(&seed);
        let aes = Aes128::new(&k);
        AesRng { aes }
    }

    pub fn random(&self, nbytes: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(nbytes);
        for i in 0..nbytes / 16 {
            let m = i as u128;
            let mut m = GenericArray::clone_from_slice(&m.to_le_bytes());
            self.aes.encrypt_block(&mut m);
            out.extend_from_slice(m.as_slice());
        }
        out[0..nbytes].to_vec()
    }
}
