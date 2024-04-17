//! Implementation of a VOLE-in-the-head protocol for non-interactive, publicly verifiable zero-
//! knowledge proofs.
//!
//! This paper implements a protocol defined by Baum et al. in _Publicly Verifiable Zero-Knowledge
//! and Post-Quantum Signatures from VOLE-in-the-head_[^vole]. Specifically, it implements the
//! zero-knowledge protocol for degree-2 relations over small- to medium-sized fields, defined in
//! Section 6.2, figure 7.
//!
//! The name of this crate derives from the "cheesehead" hats traditionally worn by fans of the
//! Packers football team. The Swiss-cheese-like holes in the hats are known as "Schmivitz".
//!
//! [^vole]: Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, Michael Klooß,
//! Emmanuela Orsini, Lawrence Roy, and Peter Scholl. [Publicly Verifiable Zero-Knowledge and
//! Post-Quantum Signatures from VOLE-in-the-head](https://eprint.iacr.org/2023/996). 2023.
//!

#![deny(missing_docs)]

pub mod all_but_one_vc;
pub mod circuit;
pub mod convert_to_vole;
pub mod parameters;
pub mod proof;
mod vole;

pub use proof::Proof;
