// line Contains the PRG and the hash stuff

use crate::parameters::SECURITY_PARAM;
// use crate::vole_prime::parameters::MAX_LIMBS_SUPPORTED;
// use crate::vole_prime::parameters::ONE_LIMB;

use crate::parameters::{MAX_LIMBS_SUPPORTED, ONE_LIMB};

use crate::vole_prime::utils::get_vec_u8_bit;

use crate::vole::crypto_primitives::{Com, H1, IV, Key, Seed};
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
};
use shake::Shake128;
use swanky_field::PrimeFiniteField;
#[cfg(test)]
use swanky_field_binary::F2;

pub(crate) struct pPRG {
    aes0: Aes128,
    counter: u128,
}

impl pPRG {
    /// Create a PRG from an an initialization vector `iv`.
    pub(crate) fn new(seed: IV, iv: IV) -> Self {
        let key: GenericArray<u8, _> = GenericArray::from(seed);
        let aes0 = Aes128::new(&key);

        let counter = u128::from_le_bytes(iv);
        Self { aes0, counter }
    }

    fn incr(&mut self) {
        self.counter += 1;
    }

    fn counter_to_bytes(&self) -> [u8; 16] {
        self.counter.to_le_bytes()
    }

    /// Function that returns two random keys.
    /// There has no associated decrypt function, it is used for its PRG properties.
    /// This function corresponds to `PRG.encrypt` in the spec.
    pub(crate) fn encrypt_double(&mut self) -> (Key, Key) {
        const BLOCKS: usize = 2;
        let block = GenericArray::from([0u8; 16]);
        let mut blocks = [block; BLOCKS];

        // encrypt blocks in place
        for block in blocks.iter_mut() {
            *block = GenericArray::from(self.counter_to_bytes());
            self.incr();
        }
        self.aes0.encrypt_blocks(&mut blocks);

        let k1 = blocks[0].into();
        let k2 = blocks[1].into();
        (k1, k2)
    }

    /// Function that returns a pseudo-random vector of F2 values
    #[cfg(test)]
    pub(crate) fn prg(mut self, l: usize) -> Vec<F2> {
        let mut res = Vec::with_capacity(l);

        let mut remaining: i64 = l.try_into().unwrap();

        const BLOCKS: usize = 16;
        let block = GenericArray::from([0u8; 16]);
        let mut blocks = [block; BLOCKS];
        while remaining > 0 {
            // encrypt blocks in place
            for block in blocks.iter_mut() {
                *block = GenericArray::from(self.counter_to_bytes());
                self.incr();
            }
            self.aes0.encrypt_blocks(&mut blocks);

            // converting blocks to F2 values and pushing them into the vector.
            for block in blocks.iter() {
                for u in block.iter() {
                    for i in 0..8u8 {
                        if remaining <= 0 {
                            return res;
                        }

                        res.push(((u >> i & 1_u8) == 1).into());
                        remaining -= 1;
                    }
                }
            }
        }

        res
    }

    pub(crate) fn prg_compact(mut self, bit_len: usize) -> Vec<u64> {
        let mut res = Vec::with_capacity(bit_len / 64 + 1);

        let mut remaining: i64 = bit_len.try_into().unwrap();

        const BLOCKS: usize = 16;
        let block = GenericArray::from([0u8; 16]);
        let mut blocks = [block; BLOCKS];
        while remaining > 0 {
            for block in blocks.iter_mut() {
                *block = GenericArray::from(self.counter_to_bytes());
                self.incr();
            }
            self.aes0.encrypt_blocks(&mut blocks);

            for block in blocks.iter() {
                let mut t: [u8; 8] = Default::default();

                t.clone_from_slice(&block[0..8]);
                let u1 = u64::from_le_bytes(t);
                res.push(u1);
                remaining -= 64;
                if remaining <= 0 {
                    return res;
                }

                t.clone_from_slice(&block[8..16]);
                let u1 = u64::from_le_bytes(t);
                res.push(u1);
                remaining -= 64;
                if remaining <= 0 {
                    return res;
                }
            }
        }

        res
    }

    /// Pseudo-random generate seeds to initialize other pseudo-random generators.
    ///
    /// This is mostly a convenience function as it could be derived from [`PRG`].
    pub(crate) fn generate_prg_seeds(mut self, repetition_param: usize) -> Vec<Seed> {
        let mut res = Vec::with_capacity(repetition_param);

        for _ in 0..repetition_param {
            let mut block = GenericArray::from(self.counter_to_bytes());
            self.aes0.encrypt_block(&mut block);
            self.incr();

            res.push(block.into());
        }
        res
    }
}

/// Use this function for the prime vole, calls the binary PRG as usual, convert the binary PRG output to prime field "PRG output"
pub(crate) fn prg_compact_to_fp<Fp: PrimeFiniteField>(
    prg_compact_vec: Vec<u64>,
    bit_len: usize,
) -> Vec<Fp> {
    let Fp_bit_len = Fp::ZERO.bit_decomposition().len();

    // NOTE: Maximum limb set to 64 for 4096 bits (64 u64)
    assert!(Fp::MIN_LIMBS_NEEDED <= MAX_LIMBS_SUPPORTED);
    assert_eq!(bit_len % Fp_bit_len, 0);
    assert!((bit_len + Fp_bit_len - 1) / Fp_bit_len <= MAX_LIMBS_SUPPORTED * ONE_LIMB);

    let prg_bytes_size = (prg_compact_vec.len() * 8) as u64;
    let prime_prg_field_vec_size = ((bit_len + (Fp_bit_len - 1)) / Fp_bit_len) as usize;

    let prg_u8_vec: Vec<u8> = prg_compact_vec
        .iter()
        .flat_map(|&x| x.to_le_bytes()) // convert each u64 to [u8; 8]
        .collect();
    assert_eq!(prg_u8_vec.len(), prg_bytes_size as usize);

    let prg_u64_vec_size = prime_prg_field_vec_size * Fp::MIN_LIMBS_NEEDED;
    let mut prg_u64_vec = vec![0u64; prg_u64_vec_size];
    let mut prg_u64_vec_idx = 0;

    'outer: for i in 0..prime_prg_field_vec_size {
        let mut val = 0;
        let mut u64_idx_counter = 0;
        for j in 0..Fp_bit_len {
            // if the ell_bit is smaller than field size, then once we copy enough, we break
            if (bit_len < Fp_bit_len) && (j >= bit_len) {
                break;
            }

            if u64_idx_counter % 64 == 0 {
                val = 0;
                u64_idx_counter = 0;
            } // if field bit size is larger than u64, we need a new u64 ...

            // The overall bit index cannot exceed the ell_hat_bit len
            if i * Fp_bit_len + j < bit_len {
                val |= (get_vec_u8_bit(prg_u8_vec.clone(), (i * Fp_bit_len + j) / 8, j % 8) as u64)
                    << u64_idx_counter % 64;
            }

            if u64_idx_counter % 64 == 63 {
                prg_u64_vec[prg_u64_vec_idx] = val;
                prg_u64_vec_idx += 1;
                u64_idx_counter = 0;
                continue;
            } // ... after setting the previous u64 here
            u64_idx_counter += 1;

            // If bit idx is not multiple of 64 and we have reached the end of prg bits, then this is the last u64, copy and break
            if (j % 64 != 63) && (i * Fp_bit_len + j >= bit_len - 1) {
                prg_u64_vec[prg_u64_vec_idx] = val;
                break 'outer;
            }

            // If bit idx is not multiple of 64 and the bit idx has reached field_size, need to copy and break
            if (j % 64 != 63) && (j >= Fp_bit_len - 1) && (Fp_bit_len >= 64) {
                prg_u64_vec[prg_u64_vec_idx] = val;
                prg_u64_vec_idx += 1;
                break;
            }
        }
        // If field size is smaller than 64, the inner loop will end before j%64, need to copy the state here
        if Fp_bit_len < 64 {
            prg_u64_vec[prg_u64_vec_idx] = val;
            prg_u64_vec_idx += 1;
        }
    }

    let mut ret = Vec::with_capacity(prime_prg_field_vec_size);
    let mut i = 0;
    for _ in 0..prg_u64_vec_size {
        if i >= prg_u64_vec_size {
            break;
        }

        // checking if ell bits are smaller than field size, then prg value
        // cannot be larger than max val,, (checking over writing bits)
        if bit_len < Fp_bit_len && Fp_bit_len <= size_of::<u128>() {
            let mut x: u128 = 0;
            for i in 0..bit_len {
                x |= (1 as u128) << i;
            }
            assert!(prg_u64_vec[0] as u128 <= x);
        }

        // log::info!("i {}", i);
        let mut prg_u64_arr = [0u64; MAX_LIMBS_SUPPORTED];
        prg_u64_arr[..Fp::MIN_LIMBS_NEEDED]
            .copy_from_slice(&prg_u64_vec[i..i + Fp::MIN_LIMBS_NEEDED]);

        let res = Fp::try_from_int(prg_u64_arr.into()).unwrap();
        ret.push(res);

        i += Fp::MIN_LIMBS_NEEDED;
    }

    return ret;
}

// pub(crate) fn h0(x: Key, iv: IV) -> (Seed, Com) {
//     let mut hasher = Shake128::default();
//     hasher.update(&x);
//     hasher.update(&iv);
//     let mut reader = hasher.finalize_xof();
//     let mut seed = [u8::default(); SECURITY_PARAM / 8];
//     let mut commitment = [u8::default(); (SECURITY_PARAM * 2) / 8];
//     reader.read(seed.as_mut_slice());
//     reader.read(commitment.as_mut_slice());
//     (seed, commitment)
// }

// pub(crate) const H1_LENGTH: usize = (SECURITY_PARAM / 8) * 2;
// pub(crate) type H1 = [u8; H1_LENGTH];

fn h1_internal(inp: &[u8], out: &mut [u8]) {
    let mut hasher = Shake128::default();
    hasher.update(inp);
    hasher.update(&[1u8]);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

pub(crate) fn h1(inp: &[u8]) -> H1 {
    let mut out = H1::default();
    h1_internal(inp, out.0.as_mut_slice());
    out
}
