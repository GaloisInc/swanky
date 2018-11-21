use numbers::{self, PRIMES, NPRIMES};
use extern_rand::Rand;
use extern_rand::Rng as OtherRng;
use extern_rand::os as randos;

pub struct Rng(randos::OsRng);

impl Rng {
    pub fn new() -> Rng {
        Rng(randos::OsRng::new().unwrap())
    }

    pub fn gen_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut res = vec![0;n];
        self.0.fill_bytes(&mut res);
        res
    }

    pub fn gen_16_bytes(&mut self) -> [u8;16] {
        let mut res = [0;16];
        self.0.fill_bytes(&mut res);
        res
    }

    pub fn gen_usize(&mut self) -> usize {
        Rand::rand(&mut self.0)
    }

    pub fn gen_u16(&mut self) -> u16 {
        Rand::rand(&mut self.0)
    }

    pub fn gen_u32(&mut self) -> u32 {
        Rand::rand(&mut self.0)
    }

    pub fn gen_u64(&mut self) -> u64 {
        Rand::rand(&mut self.0)
    }

    pub fn gen_u128(&mut self) -> u128 {
        let low64:  u64 = Rand::rand(&mut self.0);
        let high64: u64 = Rand::rand(&mut self.0);
        let (high128, _) = (high64 as u128).overflowing_shl(64) ;
        high128 + low64 as u128
    }

    pub fn gen_usable_u128(&mut self, modulus: u16) -> u128 {
        if numbers::is_power_of_2(modulus) {
            let nbits = (modulus-1).count_ones();
            if 128 % nbits == 0 {
                return self.gen_u128();
            }
        }
        let n = numbers::digits_per_u128(modulus);
        let max = (modulus as u128).checked_pow(n as u32)
            .expect(&format!("overflow with q={} n={}", modulus, n));
        self.gen_u128() % max
    }

    pub fn gen_byte(&mut self) -> u8 {
        Rand::rand(&mut self.0)
    }

    pub fn gen_bool(&mut self) -> bool {
        Rand::rand(&mut self.0)
    }

    pub fn gen_prime(&mut self) -> u16 {
        PRIMES[self.gen_byte() as usize % NPRIMES]
    }

    pub fn gen_modulus(&mut self) -> u16 {
        2 + (self.gen_u16() % 111)
    }

    pub fn gen_usable_composite_modulus(&mut self) -> u128 {
        self._gen_usable_composite_modulus().iter().fold(1, |acc, &x| {
            acc * x as u128
        })
    }

    pub fn _gen_usable_composite_modulus(&mut self) -> Vec<u16> {
        let mut x: u128 = 1;
        PRIMES.into_iter().cloned()
            .filter(|_| self.gen_bool()) // randomly take this prime
            .take_while(|&q| { // make sure that we don't overflow!
                match x.checked_mul(q as u128) {
                    None => false,
                    Some(y) => {
                        x = y;
                        true
                    },
                }
            }).collect()
    }
}
