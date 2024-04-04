//! Type aliases for the circuit testrunner. These types are purely here for testing purposes
//! and are not used in actual circuit psi example. They are mainly used to allow the test runner
//! to take any circuit and pass it to both the garbler and the evaluator
use crate::psi::circuit_psi::{evaluator::PsiEvaluator, garbler::PsiGarbler, CircuitPsi};

use fancy_garbling::BinaryBundle;

use scuttlebutt::{AesRng, Channel};

use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

/// The type of the channel used by the garbler and evaluator
pub type C = Channel<BufReader<UnixStream>, BufWriter<UnixStream>>;
/// The type of the rng used in the tests
pub type RNG = AesRng;

/// The type of evaluator used in the tests
pub type Ev = <PsiEvaluator<C, RNG> as CircuitPsi<C, RNG>>::F;
/// The type of evaluator's payload wires
pub type EvPayloadType =
    Option<Vec<BinaryBundle<<PsiEvaluator<C, RNG> as CircuitPsi<C, RNG>>::Wire>>>;
/// The type of evaluator's set wires
pub type EvSetType<'a> = &'a [BinaryBundle<<PsiEvaluator<C, RNG> as CircuitPsi<C, RNG>>::Wire>];
/// The type of evaluator's intersection bit wires
pub type EvIntersectBitVecType<'a> = &'a [<PsiEvaluator<C, RNG> as CircuitPsi<C, RNG>>::Wire];
/// The type of evaluator's output wires
pub type EvCktOut = BinaryBundle<<PsiEvaluator<C, RNG> as CircuitPsi<C, RNG>>::Wire>;

/// The type of garbler used in the tests
pub type Gb = <PsiGarbler<C, RNG> as CircuitPsi<C, RNG>>::F;
/// The type of garbler's payload wires
pub type GbPayloadType =
    Option<Vec<BinaryBundle<<PsiGarbler<C, RNG> as CircuitPsi<C, RNG>>::Wire>>>;
/// The type of garbler's set wires
pub type GbSetType<'a> = &'a [BinaryBundle<<PsiGarbler<C, RNG> as CircuitPsi<C, RNG>>::Wire>];
/// The type of garbler's intersection bit wires
pub type GbIntersectBitVecType<'a> = &'a [<PsiGarbler<C, RNG> as CircuitPsi<C, RNG>>::Wire];
/// The type of garbler's output wires
pub type GbCktOut = BinaryBundle<<PsiGarbler<C, RNG> as CircuitPsi<C, RNG>>::Wire>;
