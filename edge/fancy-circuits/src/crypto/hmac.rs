//! Circuit implementation of HMAC-SHA256.
//!
//! This module provides HMAC (Hash-based Message Authentication Code) using
//! SHA-256 as the underlying hash function.

use crate::{binary::PairwiseXor, crypto::sha::Sha256};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// Circuit for HMAC-SHA256.
///
/// HMAC is computed as: `HMAC(key, message) = H((key ⊕ opad) || H((key ⊕ ipad) || message))`
///
/// Where:
/// - `H` is SHA-256
/// - `ipad` is 0x36 repeated for the block size (512 bits)
/// - `opad` is 0x5c repeated for the block size (512 bits)
/// - `key` is padded with zeros to the block size if shorter, or hashed if longer
///
/// This implementation uses a 512-bit key (the SHA-256 block size) to avoid needing
/// to hash long keys. For shorter keys, pad with zeros to 512 bits before passing
/// to this circuit.
///
/// # Performance Note!
/// This involves parsing a circuit file, and thus is not cheap!
/// Hence, it is best to reuse this circuit if possible versus calling
/// [`HmacSha256::new`] every time this circuit is needed.
#[derive(Default)]
pub struct HmacSha256<'a> {
    sha: Sha256,
    phantom: PhantomData<&'a ()>,
}

impl<'a> HmacSha256<'a> {
    /// Create a new [`HmacSha256`] circuit.
    pub fn new() -> Self {
        Default::default()
    }

    /// Inner padding byte (0x36 = 00110110).
    const IPAD_BYTE: &'static str = "00110110";

    /// Outer padding byte (0x5C = 01011100).
    const OPAD_BYTE: &'static str = "01011100";
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for HmacSha256<'a>
where
    F::Item: 'a,
{
    /// A 512-bit key and a variable-length message.
    type Input = (&'a [F::Item; 512], &'a [F::Item]);
    /// A 256-bit HMAC tag.
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xor = PairwiseXor::new();

        let (key, message) = inputs;

        let zero = backend.constant(F2::ZERO);
        let one = backend.constant(F2::ONE);

        // Create ipad pattern (0x36 repeated 64 times for 512 bits).
        let ipad: Vec<F::Item> = Self::IPAD_BYTE
            .repeat(64) // 64 bytes = 512 bits
            .chars()
            .map(|c| if c == '1' { one.clone() } else { zero.clone() })
            .collect();

        // Create opad pattern (0x5C repeated 64 times for 512 bits).
        let opad: Vec<F::Item> = Self::OPAD_BYTE
            .repeat(64)
            .chars()
            .map(|c| if c == '1' { one.clone() } else { zero.clone() })
            .collect();

        // Compute `key ⊕ ipad`.
        let key_xor_ipad = xor.execute(backend, (key, &ipad), channel)?;

        // Compute `key ⊕ opad`.
        let key_xor_opad = xor.execute(backend, (key, &opad), channel)?;

        // Inner hash: `H((key ⊕ ipad) || message)`.
        let mut inner_input = key_xor_ipad;
        inner_input.extend_from_slice(message);
        let inner_hash = self.sha.execute(backend, inner_input, channel)?;

        // Outer hash: `H((key ⊕ opad) || inner_hash)`.
        let mut outer_input = key_xor_opad;
        outer_input.extend_from_slice(&inner_hash);
        let hmac = self.sha.execute(backend, outer_input, channel)?;

        Ok(hmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_plaintext::{Dummy, DummyVal};

    fn string_to_bool_vec(str: &str) -> Vec<DummyVal> {
        str.chars()
            .map(|c| match c {
                '0' => DummyVal::new_bool(false),
                '1' => DummyVal::new_bool(true),
                _ => panic!("Unexpected character in boolean string"),
            })
            .collect()
    }

    #[test]
    fn hmac_sha256_empty_message() {
        // Test HMAC-SHA256 with empty message
        // Key: 512 bits of zeros
        // Message: empty

        let hmac = HmacSha256::new();
        let key = [DummyVal::new_bool(false); 512];
        let message = [];

        let output = Dummy::eval(&hmac, (&key, &message)).unwrap();

        // Computed using: echo -n "" | openssl dgst -sha256 -mac hmac -macopt hexkey:$(python3 -c "print('00'*64)")
        // Result: b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1011011000010011011001111001101000001000000101001101100111101100011101110010111110010101110101110111100011000011010111111100010111111111000101101001011111000100100100110111000101010110010100111100011011000111000100100001010001000010100100101100010110101101"
        );
    }

    #[test]
    fn hmac_sha256_test_message() {
        // Test HMAC-SHA256 with "test" message
        // Key: 512 bits of zeros
        // Message: "test" = 0x74657374

        let hmac = HmacSha256::new();
        let key = [DummyVal::new_bool(false); 512];

        // "test" in binary
        // 't' = 0x74 = 01110100
        // 'e' = 0x65 = 01100101
        // 's' = 0x73 = 01110011
        // 't' = 0x74 = 01110100
        let message = string_to_bool_vec("01110100011001010111001101110100");

        let output = Dummy::eval(&hmac, (&key, &message[..])).unwrap();

        // Computed using: echo -n "test" | openssl dgst -sha256 -mac hmac -macopt hexkey:$(python3 -c "print('00'*64)")
        // Result: 43b0cef99265f9e34c10ea9d3501926d27b39f57c6d674561d8ba236e7a819fb
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "0100001110110000110011101111100110010010011001011111100111100011010011000001000011101010100111010011010100000001100100100110110100100111101100111001111101010111110001101101011001110100010101100001110110001011101000100011011011100111101010000001100111111011"
        );
    }

    #[test]
    fn hmac_sha256_with_key() {
        // Test HMAC-SHA256 with non-zero key
        // Key: "key" (0x6b6579) padded to 512 bits with zeros
        // Message: "The quick brown fox jumps over the lazy dog"

        let hmac = HmacSha256::new();

        // "key" = 0x6b6579
        // 'k' = 0x6b = 01101011
        // 'e' = 0x65 = 01100101
        // 'y' = 0x79 = 01111001
        let mut key = string_to_bool_vec("011010110110010101111001");
        // Pad to 512 bits
        key.resize(512, DummyVal::new_bool(false));
        let key: [DummyVal; 512] = key.try_into().expect("Key should contain 512 elements");

        let message = "The quick brown fox jumps over the lazy dog";
        let message: Vec<DummyVal> = message
            .bytes()
            .flat_map(|b| {
                (0..8)
                    .rev()
                    .map(move |i| DummyVal::new_bool((b >> i) & 1 == 1))
            })
            .collect();

        let output = Dummy::eval(&hmac, (&key, &message[..])).unwrap();

        // Computed using: echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha256 -mac hmac -macopt key:key
        // Result: f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1111011110111100100000111111010000110000010100111000010000100100101100010011001010011000111001101010101001101111101100010100001111101111010011010101100110100001010010010100011000010111010110011001011101000111100111011011110000101101000110100011110011011000"
        );
    }
}
