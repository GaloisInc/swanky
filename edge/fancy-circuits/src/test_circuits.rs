//! A collection of test circuits.

pub mod fancy_binary_constant {
    //! Circuits that test [`FancyBinaryConstant`].

    use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyConstant};
    use swanky_channel::Channel;
    use swanky_error::Result;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    /// Circuit for testing [`FancyBinaryConstant::constant`].
    pub struct TestBinaryConstant;
    impl<F: FancyConstant<F2>> Circuit<F> for TestBinaryConstant {
        type Input = ();
        type Output = Vec<F::Item>;

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            _: &mut Channel,
        ) -> Result<Self::Output> {
            let outputs = vec![backend.constant(F2::ZERO), backend.constant(F2::ONE)];
            Ok(outputs)
        }
    }
    impl<F: FancyConstant<F2>> CircuitInputMapper<F> for TestBinaryConstant {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert!(inputs.is_empty());
        }

        fn ninputs(&self) -> usize {
            0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    impl<F: FancyConstant<F2>> CircuitOutputMapper<F> for TestBinaryConstant {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            output
        }
    }
}

pub mod binary {
    //! Circuits that test [`FancyBinary`].

    use crate::binary::{AndMany, OrMany, XorMany};
    use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary};
    use swanky_channel::Channel;
    use swanky_error::Result;

    /// Circuit for testing [`FancyBinary::negate`].
    pub struct TestNegateGate;
    impl<F: FancyBinary> Circuit<F> for TestNegateGate {
        type Input = F::Item;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            input: Self::Input,
            _: &mut Channel,
        ) -> Result<Self::Output> {
            Ok(backend.negate(&input))
        }
    }
    impl<F: FancyBinary> CircuitInputMapper<F> for TestNegateGate {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 1);
            inputs[0].clone()
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    impl<F: FancyBinary> CircuitOutputMapper<F> for TestNegateGate {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`FancyBinary::and`].
    pub struct TestAndGate;
    impl<F: FancyBinary> Circuit<F> for TestAndGate {
        type Input = (F::Item, F::Item);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            backend.and(&inputs.0, &inputs.1, channel)
        }
    }
    impl<F: FancyBinary> CircuitInputMapper<F> for TestAndGate {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2);
            (inputs[0].clone(), inputs[1].clone())
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    impl<F: FancyBinary> CircuitOutputMapper<F> for TestAndGate {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`AndMany`].
    pub struct TestAndGateFanN(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestAndGateFanN {
        type Input = Vec<F::Item>;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            AndMany::new().execute(backend, inputs.as_slice(), channel)
        }
    }
    impl<F: FancyBinary> CircuitInputMapper<F> for TestAndGateFanN {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0);
            inputs
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    impl<F: FancyBinary> CircuitOutputMapper<F> for TestAndGateFanN {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`OrMany`].
    pub struct TestOrGateFanN(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestOrGateFanN {
        type Input = Vec<F::Item>;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            OrMany::new().execute(backend, inputs.as_slice(), channel)
        }
    }
    impl<F: FancyBinary> CircuitInputMapper<F> for TestOrGateFanN {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0);
            inputs
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    impl<F: FancyBinary> CircuitOutputMapper<F> for TestOrGateFanN {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`XorMany`].
    pub struct TestXorGateFanN(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestXorGateFanN {
        type Input = Vec<F::Item>;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            XorMany::new().execute(backend, inputs.as_slice(), channel)
        }
    }
    impl<F: FancyBinary> CircuitInputMapper<F> for TestXorGateFanN {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0);
            inputs
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    impl<F: FancyBinary> CircuitOutputMapper<F> for TestXorGateFanN {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }
}
