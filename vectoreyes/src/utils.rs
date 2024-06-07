use crate::{SimdBase8, U64x2, U8x16};

// For compatibility with scuttlebutt::Block
impl From<u128> for U8x16 {
    fn from(value: u128) -> Self {
        bytemuck::cast(value)
    }
}

// For compatibility with scuttlebutt::Block
impl From<U8x16> for u128 {
    fn from(value: U8x16) -> Self {
        bytemuck::cast(value)
    }
}

impl U8x16 {
    /// Perform a (full) 128-bit wide carryless multiply
    ///
    /// The result of the 128-bit wide carryless multiply is 256-bits. This is returned as
    /// two 128-bit values `[lower_bits, upper_bits]`.
    ///
    /// If you'd like a single 256-bit value, it can be constructed like
    /// ```
    /// # use vectoreyes::{U8x16, U8x32};
    /// let a = U8x16::from(3);
    /// let b = U8x16::from(7);
    /// let product: [U8x16; 2] = a.carryless_mul_wide(b);
    /// let product: U8x32 = product.into();
    /// # let _ = product;
    /// ```
    ///
    /// _(This function doesn't always return a `U8x32`, since it will use `__m128i` for
    /// computation on x86_64 machines, and it may be slower to always construct a `__m256i`)_
    #[inline(always)]
    pub fn carryless_mul_wide(self, b: Self) -> [Self; 2] {
        #[inline(always)]
        fn upper_bits_made_lower(a: U64x2) -> U64x2 {
            U64x2::from(U8x16::from(a).shift_bytes_right::<8>())
        }

        #[inline(always)]
        fn lower_bits_made_upper(a: U64x2) -> U64x2 {
            U64x2::from(U8x16::from(a).shift_bytes_left::<8>())
        }
        // See algorithm 2 on page 12 of https://web.archive.org/web/20191130175212/https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
        let a: U64x2 = bytemuck::cast(self);
        let b: U64x2 = bytemuck::cast(b);
        let c = a.carryless_mul::<true, true>(b);
        let d = a.carryless_mul::<false, false>(b);
        // CLMUL(lower bits of a ^ upper bits of a, lower bits of b ^ upper bits of b)
        let e = (a ^ upper_bits_made_lower(a))
            .carryless_mul::<false, false>(b ^ upper_bits_made_lower(b));
        let product_upper_half =
            c ^ upper_bits_made_lower(c) ^ upper_bits_made_lower(d) ^ upper_bits_made_lower(e);
        let product_lower_half =
            d ^ lower_bits_made_upper(d) ^ lower_bits_made_upper(c) ^ lower_bits_made_upper(e);
        [
            bytemuck::cast(product_lower_half),
            bytemuck::cast(product_upper_half),
        ]
    }
}

#[test]
fn test_carryless_mul_wide() {
    // Test some random test vectors.
    assert_eq!(
        U8x16::from(113718949524325212707291430558820879029)
            .carryless_mul_wide(U8x16::from(305595614614064458589355305592899341783)),
        [
            U8x16::from(181870553715282462853040151492428488859),
            U8x16::from(69303674900886469910632566104075007218)
        ]
    );
    assert_eq!(
        U8x16::from(305491409529336450059265117908006794202)
            .carryless_mul_wide(U8x16::from(331330386820708447646441739307072964010)),
        [
            U8x16::from(127269516908168038593688997658496458020),
            U8x16::from(125659689760004568937468201162182112345)
        ]
    );
    assert_eq!(
        U8x16::from(267625637845811074182836635736437393132)
            .carryless_mul_wide(U8x16::from(98247896988070748377279692417561622532)),
        [
            U8x16::from(47973638020603525196354339630722399152),
            U8x16::from(69947343163265692377803117866524991745)
        ]
    );
}
