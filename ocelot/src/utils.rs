use scuttlebutt::Block;

#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn get_bit(src: &[u8], i: usize) -> u8 {
    let byte = src[i / 8];
    let bit_pos = i % 8;
    (byte & (1 << bit_pos) != 0) as u8
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn set_bit(dst: &mut [u8], i: usize, b: u8) {
    let bit_pos = i % 8;
    if b == 1 {
        dst[i / 8] |= 1 << bit_pos;
    } else {
        dst[i / 8] &= !(1 << bit_pos);
    }
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn transpose_naive_inplace(dst: &mut [u8], src: &[u8], m: usize) {
    assert_eq!(src.len() % m, 0);
    let l = src.len() * 8;
    let n = l / m;

    for i in 0..l {
        let bit = get_bit(src, i);
        let (row, col) = (i / m, i % m);
        set_bit(dst, col * n + row, bit);
    }
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn transpose_naive(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    assert_eq!(nrows * ncols, input.len() * 8);
    let mut output = vec![0u8; nrows * ncols / 8];

    transpose_naive_inplace(&mut output, input, ncols);
    output
}

pub fn transpose_pre_allocated(m: &[u8], dst: &mut [u8], nrows: usize, ncols: usize) {
    assert_eq!(dst.len(), nrows * ncols / 8);
    assert_eq!(m.len(), nrows * ncols / 8);
    #[cfg(not(target_arch = "x86_64"))]
    {
        transpose_naive_inplace(dst, m, ncols);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        _transpose(dst.as_mut_ptr(), m.as_ptr(), nrows as u64, ncols as u64);
    }
}

#[inline]
pub fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        transpose_naive(m, nrows, ncols)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut m_ = vec![0u8; nrows * ncols / 8];
        _transpose(
            m_.as_mut_ptr() as *mut u8,
            m.as_ptr(),
            nrows as u64,
            ncols as u64,
        );
        m_
    }
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn _transpose(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64) {
    assert!(nrows >= 16);
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    sse_trans(out, inp, nrows, ncols)
}

#[link(name = "transpose")]
#[cfg(target_arch = "x86_64")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

// The hypothesis that a rust implementation of matrix transpose would be faster
// than the C implementation appears to be false... But let's leave this code
// here for now just in case.

// union __U128 {
//     vector: __m128i,
//     bytes: [u8; 16],
// }

// impl Default for __U128 {
//     #[inline]
//     fn default() -> Self {
//         __U128 { bytes: [0u8; 16] }
//     }
// }

// #[inline]
// pub fn transpose(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
//     assert_eq!(nrows % 16, 0);
//     assert_eq!(ncols % 16, 0);
//     let mut output = vec![0u8; nrows * ncols / 8];
//     unsafe {
//         let mut h: &[u8; 4];
//         let mut v: __m128i;
//         let mut rr: usize = 0;
//         let mut cc: usize;
//         while rr <= nrows - 16 {
//             cc = 0;
//             while cc < ncols {
//                 v = _mm_set_epi8(
//                     input[(rr + 15) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 14) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 13) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 12) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 11) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 10) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 9) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 8) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 7) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 6) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 5) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 4) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 3) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 2) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 1) * ncols / 8 + cc / 8] as i8,
//                     input[(rr + 0) * ncols / 8 + cc / 8] as i8,
//                 );
//                 for i in (0..8).rev() {
//                     h = &*(&_mm_movemask_epi8(v) as *const _ as *const [u8; 4]);
//                     output[(cc + i) * nrows / 8 + rr / 8] = h[0];
//                     output[(cc + i) * nrows / 8 + rr / 8 + 1] = h[1];
//                     v = _mm_slli_epi64(v, 1);
//                 }
//                 cc += 8;
//             }
//             rr += 16;
//         }
//         if rr == nrows {
//             return output;
//         }

//         cc = 0;
//         while cc <= ncols - 16 {
//             let mut v = _mm_set_epi16(
//                 input[((rr + 7) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 6) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 5) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 4) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 3) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 2) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 1) * ncols / 8 + cc / 8) / 2] as i16,
//                 input[((rr + 0) * ncols / 8 + cc / 8) / 2] as i16,
//             );
//             for i in (0..8).rev() {
//                 h = &*(&_mm_movemask_epi8(v) as *const _ as *const [u8; 4]);
//                 output[(cc + i) * nrows / 8 + rr / 8] = h[0];
//                 output[(cc + i) * nrows / 8 + rr / 8 + 8] = h[1];
//                 v = _mm_slli_epi64(v, 1);
//             }
//             cc += 16;
//         }
//         if cc == ncols {
//             return output;
//         }
//         let mut tmp = __U128 {
//             bytes: [
//                 input[(rr + 0) * ncols / 8 + cc / 8],
//                 input[(rr + 1) * ncols / 8 + cc / 8],
//                 input[(rr + 2) * ncols / 8 + cc / 8],
//                 input[(rr + 3) * ncols / 8 + cc / 8],
//                 input[(rr + 4) * ncols / 8 + cc / 8],
//                 input[(rr + 5) * ncols / 8 + cc / 8],
//                 input[(rr + 6) * ncols / 8 + cc / 8],
//                 input[(rr + 7) * ncols / 8 + cc / 8],
//                 0u8,
//                 0u8,
//                 0u8,
//                 0u8,
//                 0u8,
//                 0u8,
//                 0u8,
//                 0u8,
//             ],
//         };
//         for i in (0..8).rev() {
//             h = &*(&_mm_movemask_epi8(tmp.vector) as *const _ as *const [u8; 4]);
//             output[(cc + i) * nrows / 8 + rr / 8] = h[0];
//             tmp.vector = _mm_slli_epi64(tmp.vector, 1);
//         }
//     };
//     output
// }

#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}
#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
}

#[inline(always)]
pub fn xor_two_blocks(x: &(Block, Block), y: &(Block, Block)) -> (Block, Block) {
    (x.0 ^ y.0, x.1 ^ y.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _transpose(nrows: usize, ncols: usize) {
        let m = (0..nrows * ncols / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        let m_ = m.clone();
        let m = transpose(&m, nrows, ncols);
        let m = transpose(&m, ncols, nrows);
        assert_eq!(m, m_);
    }

    #[test]
    fn test_transpose() {
        _transpose(16, 16);
        _transpose(24, 16);
        _transpose(32, 16);
        _transpose(40, 16);
        _transpose(128, 16);
        _transpose(128, 24);
        _transpose(128, 128);
        _transpose(128, 1 << 16);
        _transpose(128, 1 << 18);
        _transpose(32, 32);
        _transpose(64, 32);
    }

    #[test]
    fn test_boolvec_to_u8vec() {
        let v = (0..128)
            .map(|_| rand::random::<bool>())
            .collect::<Vec<bool>>();
        let v_ = boolvec_to_u8vec(&v);
        let v__ = u8vec_to_boolvec(&v_);
        assert_eq!(v, v__);
    }

    #[test]
    fn test_u8vec_to_boolvec() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = u8vec_to_boolvec(&v);
        let v__ = boolvec_to_u8vec(&v_);
        assert_eq!(v, v__);
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_transpose(b: &mut Bencher) {
        let (nrows, ncols) = (128, 1 << 18);
        let m = (0..nrows * ncols / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| transpose(&m, nrows, ncols));
    }
}
