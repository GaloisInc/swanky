//! A collection of test circuits.

pub mod fancy_binary_constant {
    //! Circuits that test [`FancyBinaryConstant`].

    use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinaryConstant};
    use swanky_channel::Channel;
    use swanky_error::Result;

    /// Circuit for testing [`FancyBinaryConstant::constant`].
    pub struct TestBinaryConstant;
    impl<F: FancyBinaryConstant> Circuit<F> for TestBinaryConstant {
        type Input = ();
        type Output = Vec<F::Item>;

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            _: &mut Channel,
        ) -> Result<Self::Output> {
            let outputs = vec![backend.constant(false), backend.constant(true)];
            Ok(outputs)
        }
    }
    impl<F: FancyBinaryConstant> CircuitInputMapper<F> for TestBinaryConstant {
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
    impl<F: FancyBinaryConstant> CircuitOutputMapper<F> for TestBinaryConstant {
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

pub mod arithmetic {
    //! Circuits that test [`FancyArithmetic`].

    use crate::arithmetic::AddMany;
    use fancy_traits::{
        Circuit, CircuitInputMapper, CircuitOutputMapper, FancyArithmetic, FancyConstant,
    };
    use swanky_channel::Channel;
    use swanky_error::Result;

    /// Circuit for testing [`FancyArithmetic::add`].
    pub struct TestAddition(pub u16);
    impl<F: FancyArithmetic> Circuit<F> for TestAddition {
        type Input = (F::Item, F::Item);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            _: &mut Channel,
        ) -> Result<Self::Output> {
            Ok(backend.add(&inputs.0, &inputs.1))
        }
    }
    impl<F: FancyArithmetic> CircuitInputMapper<F> for TestAddition {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2);
            (inputs[0].clone(), inputs[1].clone())
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyArithmetic> CircuitOutputMapper<F> for TestAddition {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`AddMany`].
    pub struct TestAddMany(pub u16, pub usize);
    impl<F: FancyArithmetic> Circuit<F> for TestAddMany {
        type Input = Vec<F::Item>;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            AddMany::new().execute(backend, inputs.as_slice(), channel)
        }
    }
    impl<F: FancyArithmetic> CircuitInputMapper<F> for TestAddMany {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.1);
            inputs
        }

        fn ninputs(&self) -> usize {
            self.1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyArithmetic> CircuitOutputMapper<F> for TestAddMany {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`FancyArithmetic::sub`].
    pub struct TestSubtraction(pub u16);
    impl<F: FancyArithmetic> Circuit<F> for TestSubtraction {
        type Input = (F::Item, F::Item);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            _: &mut Channel,
        ) -> Result<Self::Output> {
            Ok(backend.sub(&inputs.0, &inputs.1))
        }
    }
    impl<F: FancyArithmetic> CircuitInputMapper<F> for TestSubtraction {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2);
            (inputs[0].clone(), inputs[1].clone())
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyArithmetic> CircuitOutputMapper<F> for TestSubtraction {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`FancyArithmetic::mul`].
    pub struct TestMulGate(pub u16);
    impl<F: FancyArithmetic> Circuit<F> for TestMulGate {
        type Input = (F::Item, F::Item);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            backend.mul(&inputs.0, &inputs.1, channel)
        }
    }
    impl<F: FancyArithmetic> CircuitInputMapper<F> for TestMulGate {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2);
            (inputs[0].clone(), inputs[1].clone())
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyArithmetic> CircuitOutputMapper<F> for TestMulGate {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`FancyArithmetic::mul`] using two different moduli
    /// for the inputs.
    pub struct TestMulGateUnequalMods(pub [u16; 2]);
    impl<F: FancyArithmetic> Circuit<F> for TestMulGateUnequalMods {
        type Input = (F::Item, F::Item);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            backend.mul(&inputs.0, &inputs.1, channel)
        }
    }
    impl<F: FancyArithmetic> CircuitInputMapper<F> for TestMulGateUnequalMods {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2);
            (inputs[0].clone(), inputs[1].clone())
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }
    impl<F: FancyArithmetic> CircuitOutputMapper<F> for TestMulGateUnequalMods {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`FancyArithmetic::cmul`].
    pub struct TestCmul(pub u16, pub u16);
    impl<F: FancyArithmetic> Circuit<F> for TestCmul {
        type Input = F::Item;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            input: Self::Input,
            _: &mut Channel,
        ) -> Result<Self::Output> {
            Ok(backend.cmul(&input, self.1))
        }
    }
    impl<F: FancyArithmetic> CircuitInputMapper<F> for TestCmul {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 1);
            inputs[0].clone()
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyArithmetic> CircuitOutputMapper<F> for TestCmul {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing constant gates.
    pub struct TestConstants(pub u16, pub u16);
    impl<F: FancyArithmetic + FancyConstant> Circuit<F> for TestConstants {
        type Input = F::Item;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            input: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let constant = backend.constant(self.1, self.0, channel)?;
            Ok(backend.add(&input, &constant))
        }
    }
    impl<F: FancyArithmetic + FancyConstant> CircuitInputMapper<F> for TestConstants {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 1);
            inputs[0].clone()
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyArithmetic + FancyConstant> CircuitOutputMapper<F> for TestConstants {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }
}

pub mod proj {
    //! Circuits that test [`FancyProj`].

    use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyProj};
    use swanky_channel::Channel;
    use swanky_error::Result;

    /// Circuit for testing [`FancyProj::proj`].
    pub struct TestProj(pub u16);
    impl<F: FancyProj> Circuit<F> for TestProj {
        type Input = F::Item;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            input: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let tab = (0..self.0).map(|i| (i + 1) % self.0).collect();
            backend.proj(&input, self.0, Some(tab), channel)
        }
    }
    impl<F: FancyProj> CircuitInputMapper<F> for TestProj {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 1);
            inputs[0].clone()
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyProj> CircuitOutputMapper<F> for TestProj {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }

    /// Circuit for testing [`FancyProj::proj`] using a custom truth table.
    pub struct TestProjRand(pub u16, pub Vec<u16>);
    impl<F: FancyProj> Circuit<F> for TestProjRand {
        type Input = F::Item;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            input: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            backend.proj(&input, self.0, Some(self.1.clone()), channel)
        }
    }
    impl<F: FancyProj> CircuitInputMapper<F> for TestProjRand {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 1);
            inputs[0].clone()
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }
    impl<F: FancyProj> CircuitOutputMapper<F> for TestProjRand {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            vec![output]
        }
    }
}

#[cfg(test)]
mod fancy_arithmetic {
    use crate::{
        test_circuits::arithmetic::{TestConstants, TestMulGate},
        util::RngExt,
    };
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::{RngExt as _, rng};

    #[test]
    fn constants() {
        let mut rng = rng();
        let q = rng.gen_modulus();
        let c = rng.random::<u16>() % q;
        let circ = TestConstants(q, c);

        for _ in 0..64 {
            let x = DummyVal::rand(q, &mut rng);
            let output = Dummy::eval(&circ, x).unwrap();
            assert_eq!(output.val(), (x.val() + c) % q);
        }
    }

    #[test]
    fn arithmetic_half_gate() {
        let mut rng = rng();
        let q = rng.gen_prime();
        let c = TestMulGate(q);

        for _ in 0..16 {
            let x = DummyVal::rand(q, &mut rng);
            let y = DummyVal::rand(q, &mut rng);
            let output = Dummy::eval(&c, (x, y)).unwrap();
            assert_eq!(output.val(), (x.val() * y.val()) % q);
        }
    }
}
