//! Implementation of a bloom filter.

use sha2::{Digest, Sha256};

/// Simple implementation of a Bloom Filter. Which is guaranteed to return 1 if an element
/// is in the set, but returns 1 with probability p (settable) if an item is not in the
/// set. Does not reveal what is in the set.
#[derive(Debug, PartialEq, PartialOrd)]
pub struct BloomFilter {
    bits: Vec<bool>,
    nhashes: usize,
}

impl BloomFilter {
    /// Create a new BloomFilter with `size` entries, using `nhashes` hash functions.
    pub fn new(size: usize, nhashes: usize) -> Self {
        BloomFilter {
            bits: vec![false; size],
            nhashes,
        }
    }

    /// Compute required expansion for false positive probability `p`.
    ///
    /// That is - if you plan to insert `n` items into the BloomFilter, and want a false
    /// positive probability of `p`, then you should set the BloomFilter size to
    /// `compute_expansion(p) * n`.
    pub fn compute_expansion(p: f64) -> f64 {
        -1.44 * p.log2()
    }

    /// Compute required number of hash functions for false positive probability `p`.
    pub fn compute_nhashes(p: f64) -> usize {
        (-p.log2()).ceil() as usize
    }

    /// Create a new BloomFilter with false positive probability `p` which can support up
    /// to `n` insertions.
    pub fn with_false_positive_prob(p: f64, n: usize) -> Self {
        Self::new(
            (Self::compute_expansion(p) * n as f64).ceil() as usize,
            Self::compute_nhashes(p),
        )
    }

    /// Get the number of bins in this BloomFilter.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Get the number of hash functions in this BloomFilter.
    pub fn nhashes(&self) -> usize {
        self.nhashes
    }

    /// Get bloom filter bins.
    pub fn bins(&self) -> &[bool] {
        &self.bits
    }

    /// Get bloom filter bins packed in bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        crate::utils::pack_bits(self.bins())
    }

    /// Create bloom filter from bytes.
    pub fn from_bytes(bytes: &[u8], size: usize, nhashes: usize) -> Self {
        let bits = crate::utils::unpack_bits(bytes, size);
        BloomFilter { bits, nhashes }
    }

    /// Compute the bin that this value would go to in a BloomFilter.
    ///
    /// Result must be modded by the actual size of the bloom filter to avoid out of
    /// bounds errors.
    pub fn bin<V: AsRef<[u8]>>(value: &V, hash_index: usize) -> usize {
        // TODO: This code probably needs to use fixed-size integer types in order to be portable to
        // 32-bit architectures.
        debug_assert_eq!(std::mem::size_of::<usize>(), 8);
        let mut h = Sha256::new();
        h.update((hash_index as u64).to_le_bytes());
        h.update(value);
        let hbytes = h.finalize();
        u64::from_le_bytes(
            <[u8; 8]>::try_from(&hbytes[0..8]).expect("We're getting 8 bytes specifically"),
        ) as usize
    }

    /// Insert an item into the BloomFilter.
    pub fn insert<V: AsRef<[u8]>>(&mut self, value: &V) {
        for hash_index in 0..self.nhashes {
            let i = Self::bin(value, hash_index) % self.len();
            self.bits[i] = true;
        }
    }

    /// Check whether an item exists in the BloomFilter.
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
    use crate::{AesRng, Block};
    use rand::Rng;

    #[test]
    fn test_bloom_filter_membership() {
        let mut rng = AesRng::new();
        let n = 1000;
        let nhashes = 3;
        let mut filter = BloomFilter::new(n, nhashes);
        for _ in 0..128 {
            let x = rng.gen::<Block>();
            filter.insert(&x);
            assert!(filter.contains(&x));
        }
        assert_eq!(
            filter,
            BloomFilter::from_bytes(&filter.as_bytes(), n, nhashes)
        );
    }
}
