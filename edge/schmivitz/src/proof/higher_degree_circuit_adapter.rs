//! Adapter between the higher-degree circuit API and the `FancyCircuit` proof pipeline.

use std::marker::PhantomData;

use fancy_traits::{Circuit as FancyCircuit, Fancy};
use swanky_error::Result;
use swanky_field_binary::F2;
use swanky_sieve_ir_api::{HigherDegreeBackend, HigherDegreeCircuitExecuter};

/// Adapts `HigherDegreeCircuitExecuter` to the `FancyCircuit` interface used by Schmivitz's
/// prover and verifier traversers. This lets higher-degree circuits reuse the existing proof
/// pipeline without requiring them to implement `FancyCircuit` directly, while keeping the
/// higher-degree entry points explicit.
///
/// In the future, we should reconsider whether `Fancy` should expose higher-degree constraints
/// itself, or whether both circuit APIs should converge on a shared execution trait that removes
/// the need for this adapter.
pub(super) struct HigherDegreeCircuitAdapter<'a, C, FE>(&'a C, PhantomData<FE>);

impl<'a, C, FE> HigherDegreeCircuitAdapter<'a, C, FE> {
    pub(super) fn new(circuit: &'a C) -> Self {
        Self(circuit, PhantomData)
    }
}

impl<B, C, FE> FancyCircuit<B> for HigherDegreeCircuitAdapter<'_, C, FE>
where
    B: Fancy + HigherDegreeBackend<F2, FE>,
    C: HigherDegreeCircuitExecuter<F2, FE>,
{
    type Input = ();
    type Output = Vec<B::Item>;

    fn execute(
        &self,
        backend: &mut B,
        _: Self::Input,
        _: &mut swanky_channel::Channel,
    ) -> Result<Self::Output> {
        <C as HigherDegreeCircuitExecuter<F2, FE>>::execute(self.0, backend)?;
        Ok(vec![])
    }
}
