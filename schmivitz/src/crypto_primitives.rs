/*! Cryptographic primitives used for VOLE-it-HEAD */
use crate::parameters::SECURITY_PARAM;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
#[cfg(test)]
use swanky_field_binary::F2;

/// Initialization Vector.
pub type IV = [u8; 16];
/// Key as found in the internal nodes of the Tree-PRG/GGM-tree.
pub(crate) type Key = [u8; SECURITY_PARAM / 8];
/// Commitment as generated by 1-VC.
pub(crate) type Com = [u8; (SECURITY_PARAM * 2) / 8];
/// Seed generated by 1-VC.
pub type Seed = [u8; SECURITY_PARAM / 8];

/// Pseudo random generator, specialized to 1-VC.
///
/// In general a PRG generates a stream of randomness, but the 1-VC scheme only needs
/// the PRG to generate 2 random keys from a key in the GGM tree.
/// Therefore its interface is specialized to this with the [`PRG::encrypt_double()`] function.
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct PRG {
    aes0: Aes128,
    counter: u128,
}

impl PRG {
    /// Create a PRG from an an initialization vector `iv`.
    pub fn new(seed: IV, iv: IV) -> Self {
        let key: GenericArray<u8, _> = GenericArray::from(seed);
        let aes0 = Aes128::new(&key);

        let mut counter = 0;
        for b in iv {
            counter = (counter << 8) + (b as u128);
        }
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
    pub fn encrypt_double(&mut self) -> (Key, Key) {
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

    /// Function that returns a pseudo-random vector of bits
    ///
    /// The bits are packed into `u64`. If the last `u64` has a capacity to contain more
    /// bits than requested with `l` then the user of this function is in charge to ignore
    /// the bits.
    pub fn prg_compact(mut self, l: usize) -> Vec<u64> {
        let mut res = Vec::with_capacity(l / 64 + 1);

        // using i64 to allow for negative numbers
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

            // moving blocks to u64 values and pushing them into the vector.
            for block in blocks.iter() {
                let mut t: [u8; 8] = Default::default();

                // Move 64 bits
                t.clone_from_slice(&block[0..8]);
                let u1 = u64::from_le_bytes(t);
                res.push(u1);
                remaining -= 64;
                if remaining <= 0 {
                    return res;
                }

                // Move another 64 bits
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
    /// This is mostly a convenience function as it could be derived from [`prg`].
    pub fn generate_prg_seeds(mut self, repetition_param: usize) -> Vec<Seed> {
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

/// Hash function that generates a [`Seed`] and a [`Com`]mitment from a [`Key`] and an initialization vector [`IV`].
///
/// This function is applied on the leaves keys of the Tree-PRG/GGM-tree to generate the seeds and commitments.
/// This function corresponds to the H0 in the FAEST spec, defined page 16.
pub fn h0(x: Key, iv: IV) -> (Seed, Com) {
    // Hash x||iv to generate the Key
    let mut hasher = Shake128::default();
    hasher.update(&x);
    hasher.update(&iv);

    let mut reader = hasher.finalize_xof();
    let mut seed = [u8::default(); SECURITY_PARAM / 8];
    let mut commitment = [u8::default(); (SECURITY_PARAM * 2) / 8];
    reader.read(seed.as_mut_slice());
    reader.read(commitment.as_mut_slice());

    (seed, commitment)
}

/// Type for array of bytes with 2 times the `SECURITY_PARAM`.
///
/// This type is the result of the [`h1`] hash function.
pub type H1 = [u8; (SECURITY_PARAM / 8) * 2];

fn h1_internal(inp: &[u8], out: &mut [u8]) {
    assert_eq!(out.len(), (SECURITY_PARAM / 8) * 2);
    let mut hasher = Shake128::default();
    hasher.update(inp);
    hasher.update(&[1u8]);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

/// Hash function returning returning a hash of type [`H1`].
///
/// This function operates on a slice of bytes.
pub fn h1(inp: &[u8]) -> H1 {
    let mut out = H1::default();
    h1_internal(inp, &mut out);
    out
}
