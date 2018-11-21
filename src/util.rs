use numbers;
use rand::Rng;

pub fn u128_to_bytes(x: u128) -> [u8;16] {
    unsafe {
        std::mem::transmute(x)
    }
}

pub fn bytes_to_u128(bytes: [u8;16]) -> u128 {
    unsafe {
        std::mem::transmute(bytes)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Extra Rng functions

pub trait RngExt : Rng + Sized {
    fn gen_bool(&mut self) -> bool { self.gen() }
    fn gen_u16(&mut self) -> u16 { self.gen() }
    fn gen_u32(&mut self) -> u32 { self.gen() }
    fn gen_u64(&mut self) -> u16 { self.gen() }
    fn gen_usize(&mut self) -> usize { self.gen() }

    fn gen_u128(&mut self) -> u128 {
        let low64  = self.gen_u64();
        let high64 = self.gen_u64();
        let (high128, _) = (high64 as u128).overflowing_shl(64) ;
        high128 + low64 as u128
    }

    fn gen_usable_u128(&mut self, modulus: u16) -> u128 {
        if numbers::is_power_of_2(modulus) {
            let nbits = (modulus-1).count_ones();
            if 128 % nbits == 0 {
                return self.gen_u128();
            }
        }
        let n = numbers::digits_per_u128(modulus);
        let max = (modulus as u128).checked_pow(n as u32).expect("overflow in gen_usable_u128");
        self.gen_u128() % max
    }

    fn gen_prime(&mut self) -> u16 {
        numbers::PRIMES[self.gen::<usize>() % numbers::NPRIMES]
    }

    fn gen_modulus(&mut self) -> u16 {
        2 + (self.gen::<u16>() % 111)
    }

    fn gen_usable_composite_modulus(&mut self) -> u128 {
        numbers::product(&self.gen_usable_factors())
    }

    fn gen_usable_factors(&mut self) -> Vec<u16> {
        let mut x: u128 = 1;
        numbers::PRIMES.iter().cloned()
            .filter(|_| self.gen()) // randomly take this prime
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

impl<R: Rng + Sized> RngExt for R { }
