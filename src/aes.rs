//! Implementation of AES-128 using Intel's AES-NI.

pub struct Aes128 {
    round_keys: [u8; 176],
}

impl Aes128 {
    #[inline(always)]
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [0u8; 176];
        unsafe { aesni_setup_round_keys(key.as_ptr(), rk.as_mut_ptr()) }
        Aes128 { round_keys: rk }
    }
    #[inline]
    pub fn encrypt_u8(&self, m: &[u8; 16]) -> [u8; 16] {
        let mut c = [0; 16];
        unsafe {
            aesni_encrypt_block(10, m.as_ptr(), self.round_keys.as_ptr(), c.as_mut_ptr());
        }
        c
    }
}

extern "C" {
    fn aesni_setup_round_keys(key: *const u8, round_key: *mut u8);
    fn aesni_encrypt_block(rounds: u8, input: *const u8, rkeys: *const u8, output: *mut u8);
}
