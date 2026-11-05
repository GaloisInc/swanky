//! A Rust based API for writing zero-knowledge circuits in a style compatible with
//! [SIEVE IR](https://github.com/sieve-zk/ir). This provides a programmatic way to write circuits,
//! which should be faster than parsing a circuit dynamically.
//!
//! Here's a simple example that demonstrates how to write a boolean circuit programmatically.
//! ```
//! use swanky_field_binary::F2;
//! use swanky_sieve_ir_api::*;
//!
//! fn example1<B>(backend: &mut B) -> CircuitResult<()>
//! where
//!     B: FieldBackend<F2>,
//! {
//!     let v0 = backend.input_private()?;
//!     let v1 = backend.mul(&v0, &v0)?;
//!     let v2 = backend.add(&v1, &v1)?;
//!
//!     backend.assert_zero(&v2)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! Here's another example that defines a circuit with multiple fields.
//! ```
//! use swanky_field_binary::F2;
//! use swanky_field_ff_primes::F128p;
//! use swanky_sieve_ir_api::*;
//!
//! fn helper_circuit<B>(
//!     backend: &mut B,
//!     arg1: &B::Wire,
//!     arg2: &B::Wire,
//!     arg3: &B::Wire,
//! ) -> CircuitResult<(B::Wire, B::Wire)>
//! where
//!     B: FieldBackend<F2>,
//! {
//!     let v1 = backend.add(arg1, arg2)?;
//!     let v2 = backend.add(arg3, &v1)?;
//!
//!     Ok((v1, v2))
//! }
//!
//! fn example2<B>(backend: &mut B) -> CircuitResult<()>
//! where
//!     B: FieldBackend<F2>,
//!     B: FieldBackend<F128p>,
//! {
//!     let v0 = <B as FieldBackend<F2>>::input_private(backend)?;
//!     let v1 = <B as FieldBackend<F2>>::mul(backend, &v0, &v0)?;
//!     let v2 = <B as FieldBackend<F2>>::add(backend, &v1, &v1)?;
//!
//!     <B as FieldBackend<F2>>::assert_zero(backend, &v2)?;
//!
//!     let p0 = <B as FieldBackend<F128p>>::input_private(backend)?;
//!     let p1 = <B as FieldBackend<F128p>>::input_private(backend)?;
//!     let p2 = <B as FieldBackend<F128p>>::add(backend, &p0, &p1)?;
//!     <B as FieldBackend<F128p>>::assert_zero(backend, &p2)?;
//!
//!     let (v3, v4) = helper_circuit(backend, &v0, &v1, &v2)?;
//!     <B as FieldBackend<F2>>::assert_zero(backend, &v3)?;
//!     <B as FieldBackend<F2>>::assert_zero(backend, &v4)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ```
//! use swanky_field_binary::{F2, F128b};
//! use swanky_sieve_ir_api::*;
//!
//! fn example3<B>(backend: &mut B) -> CircuitResult<()>
//! where
//!     B: HigherDegreeBackend<F2, F128b>,
//! {
//!     let v0 = backend.input_private()?;
//!     let v1 = backend.mul(&v0, &v0)?;
//!     let v2 = backend.add(&v1, &v1)?;
//!
//!     backend.assert_zero(&v2)?;
//!
//!     let inps = backend.inputs_private::<4>()?;
//!     backend.assert_zero_higher_degree(&inps, |b, x| {
//!         let x01 = b.h_mul(&x[0], &x[1])?;
//!         let x23 = b.h_mul(&x[2], &x[3])?;
//!         b.h_mul(&x01, &x23)
//!     })?;
//!     Ok(())
//! }
//! ```

#![deny(missing_docs)]

use std::fmt::Debug;
use swanky_error::{ErrorKind, swanky_error};

/// Error types for a SIEVE IR circuit.
pub type CircuitResult<T> = swanky_error::Result<T>;

/// API for field backends that conform to SIEVE IR.
pub trait FieldBackend<F> {
    /// Backend's repesentation for wire values.
    type Wire: Debug + Default + Clone + Copy;

    /// Read a public instance value.
    fn input_public(&mut self) -> CircuitResult<Self::Wire>;

    /// Read multiple public instance values.
    fn inputs_public<const LEN: usize>(&mut self) -> CircuitResult<[Self::Wire; LEN]> {
        // TODO: Use `std::array::try_from_fn` when it's stable.
        let v = (0..LEN)
            .map(|_| self.input_public())
            .collect::<CircuitResult<Vec<Self::Wire>>>()?;
        v.try_into()
            .map_err(|e| swanky_error!(ErrorKind::OtherError, "Conversion error: {e:?}"))
    }

    /// Read a private witness value.
    fn input_private(&mut self) -> CircuitResult<Self::Wire>;

    /// Read multiple private witness values.
    fn inputs_private<const LEN: usize>(&mut self) -> CircuitResult<[Self::Wire; LEN]> {
        // TODO: Use `std::array::try_from_fn` when it's stable.
        let v = (0..LEN)
            .map(|_| self.input_private())
            .collect::<CircuitResult<Vec<Self::Wire>>>()?;
        v.try_into()
            .map_err(|e| swanky_error!(ErrorKind::OtherError, "Conversion error: {e:?}"))
    }

    /// Field addition.
    fn add(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> CircuitResult<Self::Wire>;

    /// Field addition with a constant.
    fn addc(&mut self, lhs: &Self::Wire, rhs: F) -> CircuitResult<Self::Wire>;

    /// Field multiplication.
    fn mul(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> CircuitResult<Self::Wire>;

    /// Field multiplication with a constant.
    fn mulc(&mut self, lhs: &Self::Wire, rhs: F) -> CircuitResult<Self::Wire>;

    /// An assertion that the argument is zero.
    fn assert_zero(&mut self, arg: &Self::Wire) -> CircuitResult<()>;
}

/// `CircuitExecuter` abstracts over backends to execute a circuit over a single field type.
/// Note that this is necessary since Rust currently does not support higher order trait bounds. See <https://github.com/rust-lang/rust/issues/108185#issuecomment-2819123578>
pub trait CircuitExecuter<F> {
    /// The body of the circuit to execute, given a backend.
    fn execute<B: FieldBackend<F>>(&self, backend: &mut B) -> CircuitResult<()>;
}

/// A trait abstracting over backends that support higher degree constraints.
pub trait HigherDegreeBackend<F, FE>: FieldBackend<F> {
    /// Backend's repesentation for higher degree wire values.
    type HigherDegreeWire;

    /// Field addition.
    fn h_add(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire>;

    /// Field addition with a constant.
    fn h_addc(&self, lhs: &Self::HigherDegreeWire, rhs: F)
    -> CircuitResult<Self::HigherDegreeWire>;

    /// Field multiplication.
    fn h_mul(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire>;

    /// Field multiplication with a constant.
    fn h_mulc(&self, lhs: &Self::HigherDegreeWire, rhs: F)
    -> CircuitResult<Self::HigherDegreeWire>;

    /// Assert that a higher degree constraint equals 0.
    ///
    /// The callback uses the higher degree gate operations and must describe the same
    /// constraint for each backend; errors are propagated to the caller.
    fn assert_zero_higher_degree<const INPUT_LEN: usize>(
        &mut self,
        inputs: &[Self::Wire; INPUT_LEN],
        f: impl Fn(&Self, [Self::HigherDegreeWire; INPUT_LEN]) -> CircuitResult<Self::HigherDegreeWire>,
    ) -> CircuitResult<()>;
}

/// `HigherDegreeCircuitExecuter` abstracts over backends to execute a circuit that may contain
/// higher degree constraints over a single field type.
///
/// This is the [`CircuitExecuter`] equivalent for [`HigherDegreeBackend`]s.
pub trait HigherDegreeCircuitExecuter<F, FE> {
    /// The body of the circuit to execute, given a backend.
    fn execute<B: HigherDegreeBackend<F, FE>>(&self, backend: &mut B) -> CircuitResult<()>;
}

/// Implements [`HigherDegreeCircuitExecuter`] for a circuit that already implements
/// [`CircuitExecuter`] by only exercising the [`FieldBackend`] gates.
///
/// (A blanket implementation would prevent circuits from implementing
/// [`HigherDegreeCircuitExecuter`] directly, due to trait coherence.)
#[macro_export]
macro_rules! delegate_higher_degree_executer {
    ($f:ty, $fe:ty, $circuit:ty) => {
        impl $crate::HigherDegreeCircuitExecuter<$f, $fe> for $circuit {
            fn execute<B: $crate::HigherDegreeBackend<$f, $fe>>(
                &self,
                backend: &mut B,
            ) -> $crate::CircuitResult<()> {
                <Self as $crate::CircuitExecuter<$f>>::execute(self, backend)
            }
        }
    };
}
