//! Useful utility functions.

/// Pack a bit slice into bytes.
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let nbytes = (bits.len() as f64 / 8.0).ceil() as usize;
    let mut bytes = vec![0; nbytes];
    for i in 0..nbytes {
        for j in 0..8 {
            if 8 * i + j >= bits.len() {
                break;
            }
            bytes[i] |= (bits[8 * i + j] as u8) << j;
        }
    }
    bytes
}

/// Unpack a bit vector from a slice of bytes.
pub fn unpack_bits(bytes: &[u8], size: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(size);
    for (i, byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            if 8 * i + j >= size {
                break;
            }
            bits.push(((byte >> j) & 1) != 0);
        }
    }
    bits
}

/// XOR two byte arrays, outputting the result.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

/// XOR two byte arrays up to `n` bytes, outputting the result.
pub fn xor_n(a: &[u8], b: &[u8], n: usize) -> Vec<u8> {
    a[0..n]
        .iter()
        .zip(b[0..n].iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// XOR two byte arrays in place.
pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

/// XOR two byte arrays up to `n` bytes in place.
pub fn xor_inplace_n(a: &mut [u8], b: &[u8], n: usize) {
    for (a, b) in a[0..n].iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

/// AND two byte arrays, outputting the result.
pub fn and(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a & b).collect()
}

/// AND two byte arrays in place.
pub fn and_inplace(a: &mut [u8], b: &[u8]) {
    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a &= *b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v__ = xor(&v, &v_);
        let v___ = xor(&v__, &v_);
        assert_eq!(v___, v);
    }

    #[test]
    fn test_xor_inplace() {
        let mut v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let goal = v.clone();
        let v_ = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        xor_inplace(&mut v, &v_);
        xor_inplace(&mut v, &v_);
        assert_eq!(v, goal);
    }

    #[test]
    fn test_and() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = (0..128).map(|_| 0xFF).collect::<Vec<u8>>();
        let v__ = and(&v, &v_);
        assert_eq!(v__, v);
    }
}
