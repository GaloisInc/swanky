use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, PartialOrd)]
pub struct BloomFilter {
    bits: Vec<bool>,
    nhashes: usize,
}

impl BloomFilter {
    pub fn new(size: usize, nhashes: usize) -> Self {
        BloomFilter {
            bits: vec![false; size],
            nhashes,
        }
    }

    pub fn len(&self) -> usize {
        self.bits.len()
    }

    pub fn bin<V: AsRef<[u8]>>(value: &V, hash_index: usize) -> usize {
        let mut bytes = unsafe { std::mem::transmute::<usize, [u8; 8]>(hash_index) }.to_vec();
        bytes.extend(value.as_ref());
        let hbytes = Sha256::digest(&bytes);
        let mut index_bytes = [0; 8];
        for (x, y) in hbytes.iter().zip(index_bytes.iter_mut()) {
            *y = *x;
        }
        unsafe { std::mem::transmute::<[u8; 8], usize>(index_bytes) }
    }

    pub fn insert<V: AsRef<[u8]>>(&mut self, value: &V) {
        for hash_index in 0..self.nhashes {
            let i = Self::bin(value, hash_index) % self.len();
            self.bits[i] = true;
        }
    }

    pub fn contains<V: AsRef<[u8]>>(&mut self, value: &V) -> bool {
        (0..self.nhashes).all(|hash_index| {
            let i = Self::bin(value, hash_index) % self.len();
            self.bits[i]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AesRng;
    use rand::Rng;
    use crate::Block;

    #[test]
    fn test_bloom_filter_membership() {
        let mut rng = AesRng::new();
        let mut filter = BloomFilter::new(1000, 3);
        for _ in 0..128 {
            let x = rng.gen::<Block>();
            filter.insert(&x);
            assert!(filter.contains(&x));
        }
    }
}
