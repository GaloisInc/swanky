use crate::vec_wrapper::VecWrapper;
use fancy_traits::{CircuitInputMapper, Fancy, FancyBinary, FancyBinaryConstant, HasModulus};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_party::GenericParty;
use vectoreyes::U8x16;

/// A thin wrapper around an [`AuthShare`] for use as a [`Fancy`] item.
///
/// This is used to determine the [`AuthShare`] inputs to AND gates. This is
/// important because one of the assumptions that KRRW18 makes and does not
/// explicitly state is that once the authenticate shares are generated during
/// pre-processing, the garbler has to construct the authenticated share of XOR
/// and Negation gates during pre-processing in order to correctly produce known
/// AND gates.
#[derive(Clone, Copy, Default)]
pub struct Wire<P: GenericParty> {
    auth_share: AuthShare<P>,
}

impl<P: GenericParty> Wire<P> {
    /// Construct a new [`PreProcessedWire`] from an authenticated share.
    pub(crate) fn new(auth_share: AuthShare<P>) -> Self {
        Wire { auth_share }
    }
}

impl<P: GenericParty> HasModulus for Wire<P> {
    fn modulus(&self) -> u16 {
        2
    }
}

impl<P: GenericParty> core::fmt::Debug for Wire<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreProcessedWire")
            .field("auth_share", &())
            .finish()
    }
}

/// A struct which allows us to correctly correlate the indices
/// of the input wires of an AND gate, to the index of the output
/// wire of that gate. This is required in order to figure out how
/// to turn random and triples into known ones since it allows us to
/// figure out which pairs of wires need to be correlated together.
pub struct WirePreProcessor<P: GenericParty> {
    auth_shares: VecWrapper<AuthShare<P>>,
    and_gate_left_inputs: Vec<AuthShare<P>>,
    and_gate_right_inputs: Vec<AuthShare<P>>,
    delta: U8x16,
}

impl<P: GenericParty> WirePreProcessor<P> {
    /// Construct a new [`WirePreProcessor`] using a vector of [`AuthShare`]s
    /// which equals the number of AND, Input, and Constant gates in the
    /// circuit.
    pub(crate) fn new(
        auth_shares: Vec<AuthShare<P>>,
        nands: usize,
        delta: U8x16,
    ) -> WirePreProcessor<P> {
        WirePreProcessor {
            auth_shares: VecWrapper::new(auth_shares),
            and_gate_left_inputs: Vec::with_capacity(nands),
            and_gate_right_inputs: Vec::with_capacity(nands),
            delta,
        }
    }

    /// Run a circuit on [`WirePreProcessor`] and output the input and output
    /// [`AuthShare`]s of each AND gate. That is, denoting the AND gate input
    /// wires `(a, b)` and the AND gate output wire `c`, return the `a` shares,
    /// the `b` shares, and the `c` shares, in that order.
    pub(crate) fn execute<C: CircuitInputMapper<Self>>(
        mut self,
        circuit: &C,
    ) -> Result<(Vec<AuthShare<P>>, Vec<AuthShare<P>>, Vec<AuthShare<P>>)> {
        let inputs = (0..circuit.ninputs())
            .map(|_| Wire::new(self.auth_shares.next()))
            .collect();
        Channel::with(std::io::empty(), |channel| {
            circuit.execute(
                &mut self,
                <C as CircuitInputMapper<WirePreProcessor<P>>>::map(circuit, inputs),
                channel,
            )
        })?;
        Ok((
            self.and_gate_left_inputs,
            self.and_gate_right_inputs,
            self.auth_shares.into(),
        ))
    }
}

impl<P: GenericParty> FancyBinary for WirePreProcessor<P> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        Wire::new(x.auth_share ^ y.auth_share)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        self.and_gate_left_inputs.push(x.auth_share);
        self.and_gate_right_inputs.push(y.auth_share);

        let authshare = self.auth_shares.next();
        Ok(Wire::new(authshare))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        *x
    }
}

impl<P: GenericParty> Fancy for WirePreProcessor<P> {
    type Item = Wire<P>;
}

impl<P: GenericParty> FancyBinaryConstant for WirePreProcessor<P> {
    fn constant(&mut self, _: F2) -> Self::Item {
        let authshare = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta);
        Wire::new(authshare)
    }
}
