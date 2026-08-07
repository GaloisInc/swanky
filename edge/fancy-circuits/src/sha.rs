//! SHA circuits.

use crate::{BinaryCircuit, binary::BinaryConstant};
use fancy_traits::{
    Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyBinaryConstant,
};
use std::io::Cursor;
use swanky_channel::Channel;
use swanky_error::Result;

/// Circuit for the SHA-256 compression function, where the chaining values are
/// fixed to the SHA-256 IV.
pub struct Sha256CompressionFunctionFixedIV(BinaryCircuit);

impl Sha256CompressionFunctionFixedIV {
    /// Create a new [`Sha256CompressionFunctionFixedIV`] circuit.
    ///
    /// # Performance Note!
    /// This involves parsing a Bristol Format file, and thus is not cheap!
    /// Hence, it is best to reuse this circuit if possible versus calling
    /// [`Sha256CompressionFunctionFixedIV::new`] every time this circuit is
    /// needed.
    pub fn new() -> Self {
        let circuit = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-format/sha-256.txt"),
        ))
        .expect("`sha-256.txt` file should always parse correctly");
        Self(circuit)
    }
}

impl Default for Sha256CompressionFunctionFixedIV {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for Sha256CompressionFunctionFixedIV {
    type Input = [F::Item; 512];
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        input: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let output = self.0.execute(backend, input.to_vec(), channel)?;
        Ok(output
            .try_into()
            .expect("SHA-256 compression function output should always be 256 elements"))
    }
}

impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F>
    for Sha256CompressionFunctionFixedIV
{
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 512);
        inputs.try_into().unwrap()
    }

    fn ninputs(&self) -> usize {
        512
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

impl<F: FancyBinary + FancyBinaryConstant> CircuitOutputMapper<F>
    for Sha256CompressionFunctionFixedIV
{
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        output.to_vec()
    }
}

/// Circuit for the SHA-256 compression function.
pub struct Sha256CompressionFunction(BinaryCircuit);

impl Sha256CompressionFunction {
    /// Create a new [`Sha256CompressionFunction`] circuit.
    ///
    /// # Performance Note!
    /// This involves parsing a Bristol Fashion file, and thus is not cheap!
    /// Hence, it is best to reuse this circuit if possible versus calling
    /// [`Sha256CompressionFunction::new`] every time this circuit is needed.
    pub fn new() -> Self {
        let circuit = BinaryCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-fashion/sha256.txt"),
        ))
        .expect("`sha256.txt` file should always parse correctly");
        Self(circuit)
    }
}

impl Default for Sha256CompressionFunction {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for Sha256CompressionFunction {
    type Input = ([F::Item; 512], [F::Item; 256]);
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        // Bristol Fashion expects its input in the _reverse_ order of what
        // would be expected, so we need to reverse everything when building
        // the vector to pass to [`BinaryCircuit`].
        let mut combined = inputs.0.iter().rev().cloned().collect::<Vec<_>>();
        combined.extend(inputs.1.iter().rev().cloned());
        let output = self.0.execute(backend, combined, channel)?;
        Ok(output
            .try_into()
            .expect("SHA-256 compression function output should always be 256 elements"))
    }
}

impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for Sha256CompressionFunction {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 768);
        let (block, chain) = inputs.split_at(512);
        (
            block
                .to_vec()
                .try_into()
                .expect("Block should contain 512 elements"),
            chain
                .to_vec()
                .try_into()
                .expect("Chain should contain 256 elements"),
        )
    }

    fn ninputs(&self) -> usize {
        768
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

impl<F: FancyBinary + FancyBinaryConstant> CircuitOutputMapper<F> for Sha256CompressionFunction {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        output.to_vec()
    }
}

/// Circuit for SHA-256 hash function supporting arbitrary length messages.
///
/// This implementation uses the SHA-256 compression function to process multiple
/// 512-bit blocks, properly chaining the outputs for multi-block messages.
pub struct Sha256 {
    compression: Sha256CompressionFunction,
}

impl Sha256 {
    /// Create a new [`Sha256`] circuit.
    ///
    /// # Performance Note!
    /// This involves parsing a Bristol Fashion file, and thus is not cheap!
    /// Hence, it is best to reuse this circuit if possible versus calling
    /// [`Sha256::new`] every time this circuit is needed.
    pub fn new() -> Self {
        Self {
            compression: Sha256CompressionFunction::new(),
        }
    }

    /// SHA-256 initialization vector (IV).
    const IV: &'static str = "0110101000001001111001100110011110111011011001111010111010000101\
                               001111000110111011110011011100101010010101001111111101010011101\
                               001010001000011100101001001111111100110110000010101101000100011\
                               000001111110000011110110011010101101011011111000001100110100011001";
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for Sha256 {
    type Input = Vec<F::Item>;
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let message_len = inputs.len();

        let one = backend.constant(true);
        let zero = backend.constant(false);

        // Initialize the hash with SHA-256 IV.
        let mut chain: [F::Item; 256] = Self::IV
            .chars()
            .map(|c| if c == '1' { one.clone() } else { zero.clone() })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Pad the input message.
        let mut padded = inputs.clone();
        padded.push(one.clone());

        // Calculate padding: we need to reach a length ≡ 448 (mod 512).
        let current_len = padded.len();
        let target_len = if current_len <= 448 {
            448
        } else {
            (current_len + 64).div_ceil(512) * 512 - 64
        };
        let zeros_needed = target_len - current_len;
        for _ in 0..zeros_needed {
            padded.push(zero.clone());
        }

        // Append the original message length as a 64-bit big-endian integer.
        let mut length = BinaryConstant::new_with_constants(
            message_len as u128,
            64,
            Some(zero.clone()),
            Some(one.clone()),
        )
        .execute(backend, (), channel)?;
        // Constants are represented in little-endian, but here we need message
        // length to be in big-endian. So we reverse the bundle before using it.
        length.reverse();
        padded.extend_from_slice(length.wires());

        // Process each 512-bit block.
        for chunk in padded.chunks(512) {
            let block: [F::Item; 512] =
                chunk.to_vec().try_into().expect("Chunk should be 512 bits");

            chain = self.compression.execute(backend, (block, chain), channel)?;
        }

        Ok(chain)
    }
}

#[cfg(test)]
mod test {
    use crate::sha::{Sha256, Sha256CompressionFunction, Sha256CompressionFunctionFixedIV};
    use fancy_plaintext::{Dummy, DummyVal};

    #[cfg(test)]
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
    fn sha256_compression_function() {
        // Uses the test vectors found here:
        // <https://nigelsmart.github.io/MPC-Circuits/sha-256-test.txt>.

        let sha256_fixed_iv = Sha256CompressionFunctionFixedIV::new();
        let sha256 = Sha256CompressionFunction::new();

        let iv = string_to_bool_vec(
            "0110101000001001111001100110011110111011011001111010111010000101001111000110111011110011011100101010010101001111111101010011101001010001000011100101001001111111100110110000010101101000100011000001111110000011110110011010101101011011111000001100110100011001",
        ).try_into().unwrap();

        let block = [DummyVal::new_bool(false); 512];
        let output = Dummy::eval(&sha256_fixed_iv, block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1101101001010110100110001011111000010111101110011011010001101001011000100011001101010111100110010111011110011111101111101100101010001100111001011101010010010001110000001101001001100010010000111011101011111110111110011110101000011000001101111010100111011000"
        );
        let output_with_iv = Dummy::eval(&sha256, (block, iv)).unwrap();
        assert_eq!(output, output_with_iv);

        let block = string_to_bool_vec(
            "00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111000100000001000100010010000100110001010000010101000101100001011100011000000110010001101000011011000111000001110100011110000111110010000000100001001000100010001100100100001001010010011000100111001010000010100100101010001010110010110000101101001011100010111100110000001100010011001000110011001101000011010100110110001101110011100000111001001110100011101100111100001111010011111000111111",
        ).try_into().unwrap();
        let output = Dummy::eval(&sha256_fixed_iv, block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1111110010011001101000101101111110001000111101000010101001111010011110111011100111010001100000000011001111001101110001101010001000000010010101100111010101011111100111010101101110011010010100000100010010101001110011000011000101011010101111101000010010100111"
        );
        let output_with_iv = Dummy::eval(&sha256, (block, iv)).unwrap();
        assert_eq!(output, output_with_iv);

        let block = [DummyVal::new_bool(true); 512];
        let output = Dummy::eval(&sha256_fixed_iv, block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1110111100001100011101001000110111110100110110100101000010101000110101101100010000111100000000010011111011011100001111001110011101101100100111011001111110101001101000010100010110001010110111100101011011101011100001101100000010100110010001001001001011010010"
        );
        let output_with_iv = Dummy::eval(&sha256, (block, iv)).unwrap();
        assert_eq!(output, output_with_iv);

        let block = string_to_bool_vec(
            "00100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000000011011100000111001101000100101001000000100100111000001000100010100110011111001100011101000000001000001011101111101010011000111011000100111001101100100010010100010100101000001000011110011000111000110100000001001101110111101111100101010001100110110011110011010011101001000011000110110011000000101011000010100110110111110010010111110001010000110111010011111110000100110101011011010110110101010001110000100100010111",
        ).try_into().unwrap();
        let output = Dummy::eval(&sha256_fixed_iv, block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1100111100001010111001001110101101100111110100111000111111111110101110010100000001101000100110000100101100100010101010111101111001001110100100101011110001010100100011010001010001011000010111100100100011011100101010001000100000101101011110110000100111001110"
        );
        let output_with_iv = Dummy::eval(&sha256, (block, iv)).unwrap();
        assert_eq!(output, output_with_iv);
    }

    #[test]
    fn sha256_empty_string() {
        // Test SHA-256 with empty string input.
        // Expected output: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

        let sha256 = Sha256::new();
        let input = vec![];
        let output = Dummy::eval(&sha256, input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1110001110110000110001000100001010011000111111000001110000010100100110101111101111110100110010001001100101101111101110010010010000100111101011100100000111100100011001001001101110010011010011001010010010010101100110010001101101111000010100101011100001010101"
        );
    }

    #[test]
    fn sha256_abc() {
        // Test SHA-256 with "abc" input.
        // Expected output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

        let sha256 = Sha256::new();

        // "abc" in binary (ASCII encoding)
        // 'a' = 0x61 = 01100001
        // 'b' = 0x62 = 01100010
        // 'c' = 0x63 = 01100011
        let input = string_to_bool_vec("011000010110001001100011");
        let output = Dummy::eval(&sha256, input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1011101001111000000101101011111110001111000000011100111111101010010000010100000101000000110111100101110110101110001000100010001110110000000000110110000110100011100101100001011101111010100111001011010000010000111111110110000111110010000000000001010110101101"
        );
    }

    #[test]
    fn sha256_two_blocks() {
        // Test SHA-256 with a message that requires 2 blocks (> 447 bits).
        // Message: 448 bits of zeros (requires 2 blocks after padding).

        let sha256 = Sha256::new();
        let input = vec![DummyVal::new_bool(false); 448];
        let output = Dummy::eval(&sha256, input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1101010010000001011110101010010101001001011101100010100011100111110001110111111001101011011000000110000100000111000001000010101110111011101000110001001100001000100010001100010111110100011110100011011101011110011000010111100110111110011110001001111110111011"
        );
    }

    #[test]
    fn sha256_three_blocks() {
        // Test SHA-256 with a 3-block message (> 1024 bits).
        // Message: "abcd" repeated 32 times = 1024 bits = 128 bytes.

        let sha256 = Sha256::new();
        // "abcd" = 01100001 01100010 01100011 01100100
        let abcd = string_to_bool_vec("01100001011000100110001101100100");
        let mut input = Vec::with_capacity(1024);
        for _ in 0..32 {
            input.extend_from_slice(&abcd);
        }
        let output = Dummy::eval(&sha256, input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "0100010100110010111011110111001100010001000010011001001010000110000001011001101010111101100001011101010011000000011001110101011111111001011011010010010001001000101100100101100111111001010100011001001000100010101100101010110001101001101101011110101111110011"
        );
    }

    #[test]
    fn sha256_long_message() {
        let sha256 = Sha256::new();

        let message = "The quick brown fox jumps over the lazy dog";
        let input: Vec<DummyVal> = message
            .bytes()
            .flat_map(|b| {
                (0..8)
                    .rev()
                    .map(move |i| DummyVal::new_bool((b >> i) & 1 == 1))
            })
            .collect();

        let output = Dummy::eval(&sha256, input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1101011110101000111110111011001100000111110101111000000010010100011010011100101010011010101111001011000000001000001011100100111110001101010101100101000111100100011011010011110011011011011101100010110100000010110100001011111100110111110010011110010110010010"
        );
    }
}
