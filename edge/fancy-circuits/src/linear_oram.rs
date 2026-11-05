use crate::{
    BinaryBundle,
    binary::{Eq, Mux, PairwiseXor},
};
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// Circuit for running linear ORAM.
///
/// For a vector of [`BinaryBundle`]s and a single [`BinaryBundle`] query,
/// output either 0 if no match was found, or the index that matches the query.
/// Each [`BinaryBundle`] contains `N` bits.
pub struct LinearOram<const N: usize> {
    size: usize,
}

impl<const N: usize> LinearOram<N> {
    /// Create a new [`LinearOram`] containing `size` elements.
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for LinearOram<N> {
    type Input = (Vec<BinaryBundle<F::Item, N>>, BinaryBundle<F::Item, N>);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (ram, query) = inputs;

        let zero = BinaryBundle::constant(backend, 0);

        // Traverse the RAM one element at a time, and multiplex the result
        // based on whether the query matches the current index.
        let mut result = zero.clone();
        for (i, item) in ram.iter().enumerate() {
            let index = BinaryBundle::constant(backend, i as u128);
            let is_equal = Eq::default().execute(backend, (&query, &index), channel)?;
            let mux = Mux::default().execute(backend, (is_equal, &zero, item), channel)?;
            // Every `mux` but one will be zero, so we can use `PairwiseXor`
            // instead of `BinaryAddition`.
            let xor =
                PairwiseXor::default().execute(backend, (result.wires(), mux.wires()), channel)?;
            result = BinaryBundle::new(xor.try_into().expect("vector should be of length `N`"));
        }
        Ok(result)
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitInputMapper<F> for LinearOram<N> {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), (self.size + 1) * N);
        let (ram_bits, query_bits) = inputs.split_at(self.size * N);

        let ram: Vec<BinaryBundle<F::Item, N>> = ram_bits
            .chunks(N)
            .map(|chunk| {
                BinaryBundle::new(
                    chunk
                        .to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                )
            })
            .collect();
        let query = BinaryBundle::new(
            query_bits
                .to_vec()
                .try_into()
                .expect("vector should be of length `N`"),
        );

        (ram, query)
    }

    fn ninputs(&self) -> usize {
        (self.size + 1) * N
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitOutputMapper<F> for LinearOram<N> {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        output.wires().to_vec()
    }
}

#[cfg(test)]
pub mod test {
    use crate::{BinaryBundle, LinearOram};
    use fancy_plaintext::Dummy;
    use rand::RngExt;

    #[test]
    fn linear_oram() {
        const N: usize = 128;
        let mut rng = rand::rng();
        let ram_size = 10;
        let c = LinearOram::<N>::new(ram_size);

        for _ in 0..16 {
            let ram: Vec<u128> = (0..ram_size).map(|_| rng.random::<u128>()).collect();
            let index = rng.random_range(..ram_size);

            let ram_input: Vec<BinaryBundle<_, _>> =
                ram.iter().map(|&val| BinaryBundle::from(val)).collect();
            let query_input = BinaryBundle::from(index as u128);
            let output = Dummy::eval(&c, (ram_input, query_input)).unwrap();
            let result: u128 = output.into();
            assert_eq!(result, ram[index]);
        }
    }
}
