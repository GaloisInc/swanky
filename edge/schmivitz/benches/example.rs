use fancy_traits::{Circuit, FancyBinary, FancyZeroKnowledge};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;
use swanky_sieve_ir_api::{
    CircuitExecuter, CircuitResult, FieldBackend, HigherDegreeBackend, HigherDegreeCircuitExecuter,
};

pub struct ExampleCircuit<const N: usize>;

impl<F: FancyBinary + FancyZeroKnowledge<F2>, const N: usize> Circuit<F> for ExampleCircuit<N> {
    type Input = ();
    type Output = ();

    fn execute(
        &self,
        backend: &mut F,
        _: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut v = backend.witness(channel)?;
        // N additions
        for _ in 0..N {
            v = backend.xor(&v, &v);
        }

        // N multiplications
        for _ in 0..N {
            v = backend.and(&v, &v, channel)?;
        }

        // backend.assert_zero(&v2)?;

        Ok(())
    }
}

// This circuit has no higher degree constraints, so executing it on a `HigherDegreeBackend` only
// exercises the `FieldBackend` gates.
impl<FE, const N: usize> HigherDegreeCircuitExecuter<F2, FE> for ExampleCircuit<N> {
    fn execute<B: HigherDegreeBackend<F2, FE>>(&self, backend: &mut B) -> CircuitResult<()> {
        <Self as CircuitExecuter<F2>>::execute(self, backend)
    }
}

impl<const N: usize> CircuitExecuter<F2> for ExampleCircuit<N> {
    fn execute<B: FieldBackend<F2>>(&self, backend: &mut B) -> CircuitResult<()> {
        let mut v = backend.input_private()?;

        // N additions
        for _ in 0..N {
            v = backend.add(&v, &v)?;
        }

        // N multiplications
        for _ in 0..N {
            v = backend.mul(&v, &v)?;
        }

        // backend.assert_zero(&v2)?;

        Ok(())
    }
}
