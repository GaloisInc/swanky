use scuttlebutt::{field::FiniteField, AesRng};
use std::convert::TryFrom;
use vectoreyes::{
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
    SimdBase, SimdBase16, SimdBase32, SimdBase4x64, SimdBase8, SimdBase8x, U16x16, U16x8, U32x4,
    U32x8, U64x2, U64x4, U8x16, U8x32,
};

#[inline(always)] // since it's using SIMD
fn transform_random_into_arrays_of_size_ten_stored_as_a_vector(raw: [U16x8; 5]) -> [U16x16; 4] {
    // We'll take the first vector and distribute its elements to the other vectors to fill out
    // their remaining two values.
    let community_chest = raw[0];
    let combined = [raw[1], raw[2], raw[3], raw[4]].array_map(
        #[inline(always)]
        |x| U16x16::from([x, community_chest]),
    );
    // Now we need to shuffle the groups of two values that we got from the community chest.
    // U16x16 doesn't have a shuffle function, but U32x8 does! We want to move groups of two values
    // around, anyway, so we can convert our values to U32x8 and then shuffle there.
    let [a, b, c, d] = combined.array_map(
        #[inline(always)]
        |x| U32x8::from(x),
    );
    // The shuffle will affect the 8 random values that are supposed to stay together, but that's
    // fine, since we don't care if we end up shuffling our random values.
    // We say that the upper 6 values (the last 3 values of the shuffle) should be ignored, so
    // we only care about the first index here. Because we are affecting both lanes of the vector,
    // though, we need to make sure that our shuffles are permutations.
    let shuffled = [
        // This shuffle is the identity function.
        a, /*.shuffle::<3, 2, 1, 0>()*/
        b.shuffle::<0, 2, 3, 1>(),
        c.shuffle::<0, 1, 3, 2>(),
        d.shuffle::<0, 1, 2, 3>(),
    ];
    shuffled.array_map(
        #[inline(always)]
        |x| U16x16::from(x),
    )
}
#[test]
fn test_transform_random_into_arrays_of_size_ten_stored_as_a_vector() {
    let raw = bytemuck::cast::<[[u16; 8]; 5], [U16x8; 5]>([
        [0, 1, 2, 3, 4, 5, 6, 7],
        [8, 9, 10, 11, 12, 13, 14, 15],
        [16, 17, 18, 19, 20, 21, 22, 23],
        [24, 25, 26, 27, 28, 29, 30, 31],
        [32, 33, 34, 35, 36, 37, 38, 39],
    ]);
    let out: [[u16; 16]; 4] = bytemuck::cast(
        transform_random_into_arrays_of_size_ten_stored_as_a_vector(raw),
    );
    dbg!(out);
    let mut seen = std::collections::HashSet::new();
    for outer in out.iter() {
        for x in &outer[0..10] {
            assert!(seen.insert(*x), "{}", *x);
        }
    }
}

/// The input to this function is _TEN_ `u16` values stored in the lower 10 values of each vector.
/// The upper 6 values are ignored.
///
/// Invoke the provided callback several times such that, for each `input` array in inputs:
/// - `input[i]` is never opposite from itself
/// - If $`i \neq j`$, then `input[i]` will be opposite `input[j]` at least once.
#[inline(always)] // since it's using SIMD
fn visit_permutations(inputs: [U16x16; 4], mut check_equality: impl FnMut(U16x16, U16x16)) {
    // First let's replace the last 6 values in the vector with useful values.
    // Each input vector initially looks like:
    // 0 1 2 3 | 4 5 6 7 | 8 9 x x | x x x x (where x is a junk value)
    // inputs_made_hi looks like:
    // 2 3 0 1 | 6 7 4 5 | 6 7 4 5 | 2 3 0 1
    let inputs_made_hi = inputs.array_map(
        #[inline(always)]
        |x| {
            let inner_lane_shuffle = U32x8::from(x).shuffle::<2, 3, 0, 1>();
            U16x16::from(U64x4::from(inner_lane_shuffle).shuffle::<0, 1, 1, 0>())
        },
    );
    // The new inputs looks like:
    // 0 1 2 3 | 4 5 6 7 | 8 9 4 5 | 2 3 0 1
    let inputs = inputs.array_zip(inputs_made_hi).array_map(
        #[inline(always)]
        |(x, x_hi)| {
            U16x16::from(
                U32x8::from(x)
                    .blend::<true, true, true, false, false, false, false, false>(x_hi.into()),
            )
        },
    );
    // We are only shuffling in groups of two, so we can only do our current checks between indices
    // of the same parity. To get around this, we treat each pair as a 32-bit value, and then
    // perform a rotation by 16 bits.
    // inputs_rotates looks like:
    // 1 0 3 2 | 5 4 7 6 | 9 8 5 4 | 3 2 1 0
    let inputs_rotated = inputs.array_map(
        #[inline(always)]
        |x| {
            let x = U32x8::from(x);
            U16x16::from(x.shift_right::<16>() | x.shift_left::<16>())
        },
    );
    inputs.array_zip(inputs_rotated).array_for_each(
        #[inline(always)]
        |(x, x_rot)| {
            check_equality(x, U32x8::from(x).shuffle::<1, 0, 2, 3>().into());
            check_equality(x, U32x8::from(x_rot).shuffle::<1, 0, 2, 3>().into());
        },
    );
    inputs.array_zip(inputs_rotated).array_for_each(
        #[inline(always)]
        |(x, x_rot)| {
            check_equality(x, U32x8::from(x).shuffle::<2, 3, 0, 1>().into());
            check_equality(x, U32x8::from(x_rot).shuffle::<2, 3, 0, 1>().into());
        },
    );
    inputs.array_zip(inputs_rotated).array_for_each(
        #[inline(always)]
        |(x, x_rot)| {
            check_equality(x, x_rot);
        },
    );
    // At this point, the only thing we still need to do is get 6 opposite 8 and 9, and get 7
    // opposite 8 and 9.
    // 6 6 7 7 | 6 6 7 7 | 6 6 7 7 | 6 6 7 7
    let permuted = inputs.array_map(
        #[inline(always)]
        |x| {
            // 6 7 6 7 | 6 7 6 7 | 0 1 0 1 | 0 1 0 1
            let replicated = U16x16::from(U32x8::from(x).shuffle::<3, 3, 3, 3>());
            // 6 6 7 7 | 6 6 7 7 | 0 0 1 1 | 0 0 1 1
            let unpacked = replicated.unpack_lo(replicated);
            U16x16::from(U64x4::from(unpacked).shuffle::<0, 0, 0, 0>())
        },
    );
    inputs.array_zip(permuted).array_for_each(
        #[inline(always)]
        |(input, permuted)| {
            check_equality(U32x8::from(input).shuffle::<0, 0, 0, 0>().into(), permuted)
        },
    );
}

#[test]
fn test_visit_permutations() {
    let mut visited = [[[false; 10]; 10]; 4];
    visit_permutations(
        bytemuck::cast::<[[u16; 16]; 4], [U16x16; 4]>([
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255],
            [
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 255, 255, 255, 255, 255, 255,
            ],
            [
                20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 255, 255, 255, 255, 255, 255,
            ],
            [
                30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 255, 255, 255, 255, 255, 255,
            ],
        ]),
        |a, b| {
            let a = a.as_array();
            let b = b.as_array();
            // Assert that we don't confuse values from the different inputs.
            let which = a[0] / 10;
            let mut freshly_visited = 0;
            if which == 0 {
                for x in a.chunks(4) {
                    for y in x.iter() {
                        print!("{} ", *y);
                    }
                    print!("| ");
                }
                println!();
                for x in b.chunks(4) {
                    for y in x.iter() {
                        print!("{} ", *y);
                    }
                    print!("| ");
                }
                println!();
            }
            assert!(which < 4);
            for x in a.iter().copied().chain(b.iter().copied()) {
                assert_eq!(x / 10, which, "{:?}", (a, b));
            }
            let visited = &mut visited[which as usize];
            for (x, y) in a.iter().copied().zip(b.iter().copied()) {
                let x = (x % 10) as usize;
                let y = (y % 10) as usize;
                assert_ne!(x, y);
                if !visited[x][y] {
                    freshly_visited += 1;
                    assert!(!visited[y][x]);
                }
                visited[x][y] = true;
                visited[y][x] = true;
            }
            if which == 0 {
                dbg!(freshly_visited);
                println!("====");
            }
        },
    );
    println!("   0123456789");
    println!("  +----------+");
    for (i, row) in visited[0].iter().enumerate() {
        let mut count = 0;
        print!("{} |", i);
        for cell in row.iter() {
            print!("{}", if *cell { "*" } else { "." });
            if *cell {
                count += 1;
            }
        }
        println!("| SUM: {}", count);
    }
    println!("  +----------+");
    for (i, arr) in visited.iter().enumerate() {
        for (j, row) in arr.iter().enumerate() {
            for (k, cell) in row.iter().enumerate() {
                assert_eq!(j != k, *cell, "{:?}", (i, j, k));
            }
        }
    }
}

/// The upper 6 values in each vector should not be used. The lower 10 contain the indices.
#[inline(always)] // since it's using SIMD
pub(super) fn matrix_entries_vectorized(rng: &mut AesRng) -> [U16x16; 4] {
    // Since we're operating on GF(2^40), the associated prime field has a modulus of 2. As a result,
    // the prime field entry that's associated with the matrix entry is always 1.
    // These indices are supposed to be uniform mod 2^16. We can get that distribution for free by
    // just using u16 values.
    loop {
        let raw = rng.random_bits_custom_size::<5>();
        // We need to start by turning these 5 U8x16 values (which we'll be intrpreting as U16x8)
        // into U16x16 values, shuffled so that no two arrays share the same values (except in their
        // upper 2 values).
        let indices =
            transform_random_into_arrays_of_size_ten_stored_as_a_vector(bytemuck::cast(raw));
        let mut acu = 0_u32;
        visit_permutations(
            indices,
            #[inline(always)]
            |a, b| {
                acu |= U8x32::from(a.cmp_eq(b)).most_significant_bits();
            },
        );
        if acu == 0 {
            break indices;
        }
    }
}

/*// returns zero if the intersection is empty.
// TODO: make this portable?
#[inline(always)] // Due to SIMD
fn intersection_in_five(a: U16x8, b: U16x8) -> u32 {
    unsafe {
        use std::arch::x86_64::*;
        let a: __m128i = bytemuck::cast(a);
        let b: __m128i = bytemuck::cast(b);
        _mm_cmpestrc(
            a,
            5,
            b,
            5,
            _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_POSITIVE_POLARITY,
        ) as u32
    }
}

#[test]
fn test_intersection_in_five() {
    fn test_it(a: [u16; 5], b: [u16; 5]) {
        use std::collections::HashSet;
        let a_set: HashSet<u16> = IntoIterator::into_iter(a).collect();
        let b_set: HashSet<u16> = IntoIterator::into_iter(b).collect();
        let intersection = a_set.intersection(&b_set).collect::<Vec<_>>();
        let mut a_arr = [0; 8];
        a_arr[0..5].copy_from_slice(&a);
        let mut b_arr = [0; 8];
        b_arr[0..5].copy_from_slice(&b);
        let out = intersection_in_five(a_arr.into(), b_arr.into());
        println!("intersection_in_five({:?}, {:?}) = {}", a_arr, b_arr, out);
        if out == 0 {
            assert_eq!(intersection.len(), 0);
        } else {
            assert_ne!(intersection.len(), 0);
        }
    }
    test_it([0, 1, 2, 3, 4], [0xa0, 0xa1, 0xa2, 0xa3, 0xa4]);
    test_it([0xa1, 1, 2, 3, 4], [0xa0, 0xa1, 0xa2, 0xa3, 0xa4]);
    test_it([0, 1, 2, 3, 4], [0xa0, 0xa1, 4, 0xa3, 0xa4]);
}*/

// intersection_in_five checks to see whether the first five elements of its arguments intersect.
#[inline(always)] // Due to SIMD
fn visit_pairs<const N: usize>(
    indices: [[U16x8; 2]; N],
    mut intersection_in_five: impl FnMut(U16x8, U16x8),
    mut check_equality_8: impl FnMut(U16x8, U16x8),
    mut check_equality_16: impl FnMut(U16x16, U16x16),
) where
    ArrayUnrolledOps: UnrollableArraySize<N>,
{
    indices.array_for_each(
        #[inline(always)]
        |[five_a, five_b]| intersection_in_five(five_a, five_b),
    );
    indices.array_for_each(
        #[inline(always)]
        |[five_a, five_b]| {
            check_equality_8(
                // We want to construct [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
                // This is equivalent to casting five_a and five_b to U64x2 and then calling unpack_lo.
                U16x8::from(U64x2::from(five_a).unpack_lo(U64x2::from(five_b))),
                // [a[4], a[4], a[4], a[4], b[4], b[4], b[4], b[4]]
                {
                    let hi = {
                        // This outputs [?, ?, ?, ?, b[4], b[4], b[4], b[4]]
                        // TODO: use vectoreyes for this
                        five_b.shuffle_hi::<0, 0, 0, 0>()
                    };
                    let lo = {
                        // This outputs [a[4], a[4], a[4], a[4], a[4], a[4], a[4], a[4]]
                        U16x8::broadcast_lo(U16x8::from(
                            U32x4::from(five_a).shuffle::<2, 2, 2, 2>(),
                        ))
                    };
                    lo.blend::<true, true, true, true, false, false, false, false>(hi)
                },
            );
            // TODO: try without the ymm registers
            let fives = U16x16::from([five_a, five_b]);
            check_equality_16(
                // For each half (five_a, five_b), [half[0], half[1], half[0], half[1], half[0], half[1], half[2], half[3]]
                U16x16::from(U32x8::from(fives).shuffle::<1, 0, 0, 0>()),
                {
                    // For each half, produce [half[1], half[0], half[2], half[2], half[3], half[3], half[3], half[2]]
                    const SHUFFLE: U8x32 = {
                        let u16_indices: [u8; 8] = [1, 0, 2, 2, 3, 3, 3, 2];
                        let mut u8_indices: [u8; 16] = [0; 16];
                        let mut i = 0;
                        while i < 8 {
                            u8_indices[i * 2] = u16_indices[i] * 2;
                            u8_indices[i * 2 + 1] = u16_indices[i] * 2 + 1;
                            i += 1;
                        }
                        let mut u8_indices_doubled: [u8; 32] = [0; 32];
                        let mut i = 0;
                        while i < 16 {
                            u8_indices_doubled[i] = u8_indices[i];
                            u8_indices_doubled[i + 16] = u8_indices[i];
                            i += 1;
                        }
                        U8x32::from_array(u8_indices_doubled)
                    };
                    let fives = U8x32::from(fives);
                    let shuffled = fives.shuffle(SHUFFLE);
                    U16x16::from(shuffled)
                },
            );
        },
    );
}
#[test]
fn test_visit_pairs() {
    let matrix = std::cell::RefCell::new([[false; 10]; 10]);
    visit_pairs(
        [[
            [0, 1, 2, 3, 4, 99, 99, 99].into(),
            [5, 6, 7, 8, 9, 99, 99, 99].into(),
        ]],
        |a, b| {
            let mut matrix = matrix.borrow_mut();
            for a in &a.as_array()[0..5] {
                for b in &b.as_array()[0..5] {
                    matrix[*a as usize][*b as usize] = true;
                    matrix[*b as usize][*a as usize] = true;
                }
            }
        },
        |a, b| {
            dbg!(a, b);
            let mut matrix = matrix.borrow_mut();
            for (a, b) in a.as_array().array_zip(b.as_array()) {
                matrix[a as usize][b as usize] = true;
                matrix[b as usize][a as usize] = true;
            }
        },
        |a, b| {
            dbg!(a, b);
            let mut matrix = matrix.borrow_mut();
            for (a, b) in a.as_array().array_zip(b.as_array()) {
                matrix[a as usize][b as usize] = true;
                matrix[b as usize][a as usize] = true;
            }
        },
    );
    let matrix = matrix.borrow();
    println!("  0123456789");
    for (i, row) in matrix.iter().enumerate() {
        print!("{} ", i);
        for col in row.iter() {
            print!("{}", *col as u32);
        }
        println!();
    }
    for i in 0..10 {
        for j in 0..10 {
            assert_eq!(matrix[i][j], i != j);
        }
    }
}

/*#[inline(always)] // Due to SIMD
fn any_duplicates<const N: usize>(indices: [[U16x8; 2]; N]) -> bool
where
    ArrayUnrolledOps: UnrollableArraySize<N>,
{
    let mut acu0 = 0;
    let mut acu1 = 0;
    let mut acu2 = 0;
    visit_pairs(
        indices,
        #[inline(always)]
        |a, b| {
            acu0 |= intersection_in_five(a, b);
        },
        |a, b| {
            acu1 |= U8x16::from(a.cmp_eq(b)).most_significant_bits();
        },
        |a, b| {
            acu2 |= U8x32::from(a.cmp_eq(b)).most_significant_bits();
        },
    );
    (acu0 | acu1 | acu2) != 0
}*/

#[inline(always)] // since it's using SIMD
fn extract_l(a: U16x8, b: U16x8) -> U16x8 {
    let a = U8x16::from(a).shift_bytes_right::<6>();
    let b = U8x16::from(b).shift_bytes_right::<10>();
    let a = U16x8::from(a);
    let b = U16x8::from(b);
    a.blend::<false, false, false, false, false, true, true, true>(b)
}
#[test]
fn test_extract_l() {
    let out = extract_l(
        [0, 1, 2, 3, 4, 5, 6, 7].into(),
        [10, 11, 12, 13, 14, 15, 16, 17].into(),
    );
    assert_eq!(&out.as_array()[0..5], &[15, 16, 17, 6, 7]);
}

#[inline(always)] // since it's using SIMD
fn extract_indices(raw: [U16x8; 5]) -> [[U16x8; 2]; 4] {
    [
        [raw[0], raw[1]],
        [raw[2], raw[3]],
        [raw[4], extract_l(raw[3], raw[4])],
        [
            {
                // [raw[2][5], raw[2][6], raw[2][7], raw[0][5], raw[3][5]]
                let a = U16x8::from(U8x16::from(raw[0]).shift_bytes_right::<4>());
                let b = U16x8::from(U8x16::from(raw[2]).shift_bytes_right::<10>());
                let c = U16x8::from(U8x16::from(raw[3]).shift_bytes_right::<2>());
                a.blend::<false, false, false, false, false, true, true, true>(b)
                    .blend::<false, false, false, true, false, false, false, false>(c)
            },
            extract_l(raw[0], raw[1]),
        ],
    ]
}

#[test]
fn test_extract_indices() {
    let mut raw = [[0_u16; 8]; 5];
    for (i, arr) in raw.iter_mut().enumerate() {
        for (j, dst) in arr.iter_mut().enumerate() {
            *dst = (i * 10 + j) as u16;
        }
    }
    let raw: [U16x8; 5] = bytemuck::cast(raw);
    let mut seen = std::collections::HashSet::<u16>::new();
    for [a, b] in dbg!(extract_indices(raw)) {
        for x in a.as_array()[0..5].iter().chain(b.as_array()[0..5].iter()) {
            assert!(seen.insert(x.clone()), "{} is a duplicate", x);
        }
    }
}

/*#[inline(always)] // since it's using SIMD
pub(super) fn matrix_entries_vectorized2(rng: &mut AesRng) -> [[U16x8; 2]; 4] {
    // Since we're operating on GF(2^40), the associated prime field has a modulus of 2. As a result,
    // the prime field entry that's associated with the matrix entry is always 1.
    // These indices are supposed to be uniform mod 2^16. We can get that distribution for free by
    // just using u16 values.
    loop {
        let raw: [U16x8; 5] = bytemuck::cast(rng.random_bits_custom_size::<5>());
        let indices = extract_indices(raw);
        let b = !any_duplicates(indices);
        // Indicate b is unlikely. See https://docs.rs/likely_stable/latest/src/likely_stable/lib.rs.html#77
        if (1i32).checked_div(if b { 0 } else { 1 }).is_none() {
            break indices;
        }
    }
}*/

pub(super) fn matrix_entries<'a, FE: FiniteField>(
    rng: &'a mut AesRng,
) -> impl Iterator<Item = [(u16, FE); 10]> + 'a {
    std::iter::repeat_with(move || {
        matrix_entries_vectorized(rng).array_zip(<[[FE; 10]; 4]>::array_generate(|_| {
            <[FE; 10]>::array_generate(|_| FE::random_nonzero(rng))
        }))
    })
    .flat_map(IntoIterator::into_iter)
    .map(|(indices, field_elements)| {
        <&[u16; 10]>::try_from(&indices.as_array()[0..10])
            .expect("We only asked for 10 entries!")
            .array_zip(field_elements)
    })
}
