use fancy_traits::{
    Circuit, Fancy, FancyBinary, FancyBinaryConstant, FancyEncode, FancyZeroKnowledge, HasModulus,
};
use mac_n_cheese_sieve_parser::WireId;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, bail, swanky_error};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};
use swanky_sieve_ir_api::FieldBackend;

use crate::proof::ChiGenerator;
use crate::vole::RandomVoleP;

/// A [`ProverTraverser`] allows the prover to execute the gate-by-gate evaluation portion of the
/// VOLE-in-the-head protocol.
///
/// The primary steps in circuit traversal include assigning VOLEs to each wire and
/// computing the two aggregated values used in the proof.
pub struct ProverTraverser<Vole> {
    /// Current position for a fresh extended witness value.
    wire_values_pos: WireId,

    /// Map containing the wire values for the extended witness (private inputs and multiplication gates in the circuit).
    extended_witness: Vec<F2>,
    /// Fiat-Shamir challenges as powers of chi. There should be one for each polynomial (e.g. non-linear gate) and assert zero.
    chi_challenge: ChiGenerator,

    /// Random VOLE values. There should be one for each extended witness value.
    voles: Vole,
    /// Count of how many of the custom VOLEs have been assigned.
    vole_assignment_count: usize,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,1}`$$.
    aggregate_degree_0: F128b,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,0}`$$.
    aggregate_degree_1: F128b,

    /// Partial aggregation of the assert zero check.
    /// TODO: Add this to the specification and reference it.
    aggregate_assert_zero: F128b,
}

impl<Vole: RandomVoleP> ProverTraverser<Vole> {
    /// Create a new circuit traverser.
    ///
    /// Requirements on inputs:
    /// - The `extended_witness` must contain a corresponding value for the input and output wires on
    ///   every non-linear gate;
    /// - The challenges must correspond to the number of polynomials. In this setting, that must
    ///   be no greater than the length of the extended witness (as defined by the [`RandomVole`]);
    /// - The [`RandomVole::extended_witness_length()`] must be large enough to have a VOLE
    ///   corresponding to every gate in the extended witness.
    pub(crate) fn new(
        extended_witness: Vec<F2>,
        chi_challenge: ChiGenerator,
        voles: Vole,
    ) -> Result<Self> {
        // TODO: debug_assert!(extended_witness.len() == voles.extended_witness_length())
        Ok(Self {
            wire_values_pos: 0,
            extended_witness,
            chi_challenge,

            voles,
            vole_assignment_count: 0,

            aggregate_degree_0: F128b::ZERO,
            aggregate_degree_1: F128b::ZERO,

            aggregate_assert_zero: F128b::ZERO,
        })
    }

    fn next_vole(&mut self) -> Result<F128b> {
        let next_index = self.vole_assignment_count;
        self.vole_assignment_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.voles.extended_witness_length() {
            bail!(
                ErrorKind::OtherError,
                "Bad input: needed at least {} VOLEs, but only got {}",
                self.vole_assignment_count,
                self.voles.extended_witness_length()
            )
        }

        self.voles.vole_mask(next_index)
    }

    /// Decomposes into the aggregate components that we constructed during the
    /// full circuit traversal.
    ///
    /// The components that were passed to [`Self::new()`] are returned unchanged.
    ///
    /// This will fail if there were unused challenges or VOLEs.
    pub(crate) fn into_parts(self) -> Result<(F128b, F128b, F128b, Vole)> {
        if self.vole_assignment_count != self.voles.extended_witness_length() {
            bail!(
                ErrorKind::OtherError,
                "Traversal contained more VOLEs than it needed! Had {}, used {}",
                self.voles.extended_witness_length(),
                self.vole_assignment_count
            );
        }
        Ok((
            self.aggregate_degree_0,
            self.aggregate_degree_1,
            self.aggregate_assert_zero,
            self.voles,
        ))
    }

    /// Get the next extended witness value.
    pub(crate) fn next_witness_value(&mut self) -> Result<F2> {
        let wid = self.wire_values_pos;
        self.wire_values_pos += 1;

        self.extended_witness
            .get::<usize>(
                wid.try_into()
                    .map_err(|e| swanky_error!(ErrorKind::OtherError, "Conversion error: {e}"))?,
            )
            .ok_or_else(|| {
                swanky_error!(
                    ErrorKind::OtherError,
                    "Internal invariant failed: expected a witness value for wire ID {}",
                    wid
                )
            })
            .copied()
    }

    /// Run `circuit` using [`ProverTraverser`].
    pub(crate) fn execute<C: Circuit<Self, Input = ()>>(&mut self, circuit: &C) -> Result<()> {
        Channel::with(std::io::empty(), |channel| {
            circuit.execute(self, (), channel)?;
            Ok(())
        })
    }
}

/// An [`F2`] element alongside its associated VOLE tag.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire(F2, F128b);

impl HasModulus for Wire {
    fn modulus(&self) -> u16 {
        2
    }
}

// TODO: Remove! This API has been replaced with the `fancy-traits::Circuit`
// API. We're keeping this around for now for backwards compatibility.
impl<VOLE: RandomVoleP> FieldBackend<F2> for ProverTraverser<VOLE> {
    type Wire = (F2, F128b);

    fn input_public(&mut self) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `input_public`")
    }

    fn input_private(&mut self) -> Result<Self::Wire> {
        let f = self.next_witness_value()?;
        let vole = self.next_vole()?;
        // Private input gates don't define a polynomial that would contribute to the aggregated
        // coefficients being computed
        Ok((f, vole))
    }

    fn add(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> Result<Self::Wire> {
        let res = lhs.0 + rhs.0;
        // Compute the correct VOLE for the output wire
        let sum_vole = lhs.1 + rhs.1;
        // Linear gates don't contribute to the aggregated values being computed
        Ok((res, sum_vole))
    }

    fn addc(&mut self, lhs: &Self::Wire, rhs: F2) -> Result<Self::Wire> {
        Ok((lhs.0 + rhs, lhs.1))
    }

    fn mul(&mut self, left: &Self::Wire, right: &Self::Wire) -> Result<Self::Wire> {
        let f = self.next_witness_value()?;

        // Assign a fresh VOLE to the output wire and get the corresponding challenge
        let vole = self.next_vole()?;
        let challenge = self.chi_challenge.next();

        // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let degree_0_coeff = left.1 * right.1;
        let degree_1_coeff = right.0 * left.1 + left.0 * right.1 - vole;

        self.aggregate_degree_0 += challenge * degree_0_coeff;
        self.aggregate_degree_1 += challenge * degree_1_coeff;

        Ok((f, vole))
    }

    fn mulc(&mut self, _: &Self::Wire, _: F2) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `mulc`")
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        let challenge = self.chi_challenge.next();
        self.aggregate_assert_zero += challenge * wire.1;
        Ok(())
    }
}

impl<VOLE: RandomVoleP> Fancy for ProverTraverser<VOLE> {
    type Item = Wire;
}

impl<VOLE: RandomVoleP> FancyBinaryConstant for ProverTraverser<VOLE> {
    fn constant(&mut self, constant: bool) -> Self::Item {
        Wire(F2::from(constant), F128b::ZERO)
    }
}

impl<VOLE: RandomVoleP> FancyEncode for ProverTraverser<VOLE> {
    fn encode_many(&mut self, _: &[u16], _: &[u16], _: &mut Channel) -> Result<Vec<Self::Item>> {
        bail!(
            ErrorKind::OtherError,
            "Invalid input: VOLE-in-the-head does not support encode"
        )
    }

    fn receive_many(&mut self, moduli: &[u16], _: &mut Channel) -> Result<Vec<Self::Item>> {
        let mut output = Vec::with_capacity(moduli.len());
        for _ in 0..moduli.len() {
            let f = self.next_witness_value()?;
            let vole = self.next_vole()?;

            // Private input gates don't define a polynomial that would contribute to the aggregated
            // coefficients being computed
            output.push(Wire(f, vole));
        }
        Ok(output)
    }
}

impl<VOLE: RandomVoleP> FancyBinary for ProverTraverser<VOLE> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let res = x.0 + y.0;

        // Compute the correct VOLE for the output wire
        let sum_vole = x.1 + y.1;

        // Linear gates don't contribute to the aggregated values being computed
        Wire(res, sum_vole)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        let f = self.next_witness_value()?;

        // Assign a fresh VOLE to the output wire and get the corresponding challenge
        let vole = self.next_vole()?;
        let challenge = self.chi_challenge.next();

        // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let degree_0_coeff = x.1 * y.1;
        let degree_1_coeff = y.0 * x.1 + x.0 * y.1 - vole;

        self.aggregate_degree_0 += challenge * degree_0_coeff;
        self.aggregate_degree_1 += challenge * degree_1_coeff;

        Ok(Wire(f, vole))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        Wire(x.0 + F2::ONE, x.1)
    }
}

impl<VOLE: RandomVoleP> FancyZeroKnowledge for ProverTraverser<VOLE> {
    fn assert_zero(&mut self, value: &Self::Item, _: &mut Channel) -> Result<()> {
        let challenge = self.chi_challenge.next();
        self.aggregate_assert_zero += challenge * value.1;
        Ok(())
    }
}
