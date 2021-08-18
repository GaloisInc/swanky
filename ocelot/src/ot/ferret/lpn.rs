use rand::{CryptoRng, Rng, SeedableRng};

use scuttlebutt::{AesRng, Block};
use std::ops::BitXorAssign;

use super::util::unique_random_array;

// GF2 Local Linear Code with parameter D
#[derive(Debug)]
pub struct LLCode<const ROWS: usize, const COLS: usize, const D: usize> {
    indexes: Vec<[usize; D]>,
}

impl<const ROWS: usize, const COLS: usize, const D: usize> LLCode<ROWS, COLS, D> {
    pub fn from_seed(seed: Block) -> Self {
        let mut rng = AesRng::from_seed(seed);
        Self::gen(&mut rng)
    }

    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut code = LLCode {
            indexes: Vec::with_capacity(COLS),
        };
        for _ in 0..COLS {
            code.indexes.push(unique_random_array(rng, ROWS))
        }
        code
    }

    #[inline(never)]
    pub fn mul<T: BitXorAssign + Default + Copy>(&self, v: &[T; ROWS]) -> Vec<T> {
        let mut r = Vec::with_capacity(COLS);
        for col in self.indexes.iter() {
            let mut cord = Default::default();
            for i in col.iter().copied() {
                cord ^= v[i];
            }
            r.push(cord);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROWS: usize = 30;
    const COLS: usize = 50;
    const D: usize = 10;

    use std::convert::TryInto;

    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_bool_linear() {
        let mut rng = StdRng::seed_from_u64(0x5322_FA41_6AB1_521A);
        for _ in 0..10 {
            let code: LLCode<ROWS, COLS, D> = LLCode::gen(&mut rng);

            let a: Vec<bool> = (0..ROWS).map(|_| rng.gen()).collect();
            let b: Vec<bool> = (0..ROWS).map(|_| rng.gen()).collect();
            let ab: Vec<bool> = (0..ROWS).map(|i| a[i] ^ b[i]).collect();

            let a_c = code.mul((&a[..]).try_into().unwrap());
            let b_c = code.mul((&b[..]).try_into().unwrap());
            let ab_c = code.mul((&ab[..]).try_into().unwrap());
            let a_c_b_c: Vec<bool> = (0..COLS).map(|i| a_c[i] ^ b_c[i]).collect();
            assert_eq!(a_c_b_c, ab_c);
        }
    }

    #[test]
    fn test_block_linear() {
        let mut rng = StdRng::seed_from_u64(0x5322_FA41_6AB1_521A);
        for _ in 0..10 {
            let code: LLCode<ROWS, COLS, D> = LLCode::gen(&mut rng);

            let a: Vec<Block> = (0..ROWS).map(|_| rng.gen()).collect();
            let b: Vec<Block> = (0..ROWS).map(|_| rng.gen()).collect();
            let ab: Vec<Block> = (0..ROWS).map(|i| a[i] ^ b[i]).collect();

            let a_c = code.mul((&a[..]).try_into().unwrap());
            let b_c = code.mul((&b[..]).try_into().unwrap());
            let ab_c = code.mul((&ab[..]).try_into().unwrap());
            let a_c_b_c: Vec<Block> = (0..COLS).map(|i| a_c[i] ^ b_c[i]).collect();
            assert_eq!(a_c_b_c, ab_c);
        }
    }
}
