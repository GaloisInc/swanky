use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U8x16};

pub struct PseudorandomCode {
    cipher1: Aes128EncryptOnly,
    cipher2: Aes128EncryptOnly,
    cipher3: Aes128EncryptOnly,
    cipher4: Aes128EncryptOnly,
}

impl PseudorandomCode {
    pub fn new(k1: U8x16, k2: U8x16, k3: U8x16, k4: U8x16) -> Self {
        let cipher1 = Aes128EncryptOnly::new_with_key(k1);
        let cipher2 = Aes128EncryptOnly::new_with_key(k2);
        let cipher3 = Aes128EncryptOnly::new_with_key(k3);
        let cipher4 = Aes128EncryptOnly::new_with_key(k4);
        Self {
            cipher1,
            cipher2,
            cipher3,
            cipher4,
        }
    }

    pub fn encode(&self, m: U8x16, out: &mut [U8x16; 4]) {
        out[0] = self.cipher1.encrypt(m);
        out[1] = self.cipher2.encrypt(m);
        out[2] = self.cipher3.encrypt(m);
        out[3] = self.cipher4.encrypt(m);
    }
}
