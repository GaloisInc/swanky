use rand::Rng;

use std::ops::BitXorAssign;

use super::util::unique_random_array;

// GF2 Local Linear Code with parameter D
pub struct LLCode<const ROWS: usize, const COLS: usize, const D: usize> {
    indexes: Box<[[usize; D]; COLS]>,
}

impl<const ROWS: usize, const COLS: usize, const D: usize> LLCode<ROWS, COLS, D> {
    pub fn gen<R: Rng>(rng: &mut R) -> Self {
        let mut code = LLCode {
            indexes: Box::new([[0usize; D]; COLS]),
        };
        for col in code.indexes.iter_mut() {
            *col = unique_random_array(rng, ROWS);
        }
        code
    }

    pub fn mul<T: BitXorAssign + Default + Copy>(&self, v: &[T; ROWS]) -> Vec<T> {
        let mut r = Vec::with_capacity(v.len());
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
