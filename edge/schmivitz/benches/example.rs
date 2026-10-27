use fancy_traits::{Circuit, FancyBinary, FancyZeroKnowledge};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

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
        let mut v = backend.receive(channel)?;

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
