use fancy_traits::{Circuit, CircuitInputMapper, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

mod parser;

/// A binary circuit represented as a vector of gates.
///
/// Wires are numbered canonically: the input wires are wires `0..ninputs`, and
/// the output wire of the `i`th gate is wire `ninputs + i`. Because a gate's
/// output wire is implied by its position, gates only store their _input_
/// wires, and [`Circuit::execute`] can evaluate the circuit by appending each
/// gate's output to a single buffer of wires, instead of writing into a
/// pre-initialized one.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryCircuit {
    gates: Vec<BinaryGate>,
    ninputs: usize,
    output_refs: Vec<u32>,
}

impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryCircuit {
    type Input = Vec<F::Item>;
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.len(), self.ninputs);
        // The wires of the circuit, indexed by wire number. Since the `i`th gate
        // writes wire `ninputs + i`, and gates are in topological order, we can
        // simply append each gate's output wire as we go, reusing the input
        // vector as the start of the buffer.
        let mut wires = inputs;
        wires.resize(self.ninputs + self.gates.len(), F::Item::default());
        for (i, gate) in self.gates.iter().enumerate() {
            let wire = match *gate {
                BinaryGate::Xor { xref, yref } => {
                    backend.xor(&wires[xref as usize], &wires[yref as usize])
                }
                BinaryGate::And { xref, yref } => {
                    backend.and(&wires[xref as usize], &wires[yref as usize], channel)?
                }
                BinaryGate::Inv { xref } => backend.negate(&wires[xref as usize]),
            };
            wires[self.ninputs + i] = wire;
        }
        let mut outputs = Vec::with_capacity(self.output_refs.len());
        for i in self.output_refs.iter() {
            outputs.push(wires[*i as usize].clone());
        }
        Ok(outputs)
    }
}

impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for BinaryCircuit {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.ninputs);
        inputs
    }

    fn ninputs(&self) -> usize {
        self.ninputs
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

/// Binary gates used by [`BinaryCircuit`].
// We use `u32` here on purpose to reduce the size of the `BinaryCircuit`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinaryGate {
    /// XOR gate.
    Xor {
        /// Left input wire index.
        xref: u32,
        /// Right input wire index.
        yref: u32,
    },
    /// AND gate.
    And {
        /// Left input wire index.
        xref: u32,
        /// Right input wire index.
        yref: u32,
    },
    /// NOT gate.
    Inv {
        /// Input wire index.
        xref: u32,
    },
}

/// Number of [`BinaryGate`] types.
const N_GATE_TYPES: usize = 3;

impl std::fmt::Display for BinaryGate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Xor { xref, yref } => write!(f, "Xor ( {}, {} )", xref, yref),
            Self::And { xref, yref } => write!(f, "And ( {}, {} )", xref, yref),
            Self::Inv { xref } => write!(f, "Inv ( {} )", xref),
        }
    }
}

impl BinaryCircuit {
    /// Construct a new empty [`BinaryCircuit`] on `ninputs` inputs, allocating
    /// `ngates` of space to store gates if provided.
    pub fn new(ninputs: usize, ngates: Option<usize>) -> Self {
        let gates = if let Some(n) = ngates {
            Vec::with_capacity(n)
        } else {
            Vec::new()
        };
        Self {
            gates,
            ninputs,
            output_refs: Vec::new(),
        }
    }

    /// Reorder the circuit's gates into long batches of same-type gates,
    /// preserving the circuit's semantics.
    ///
    /// Circuit files interleave their gate types more or less arbitrarily, which
    /// makes the gate-type dispatch in [`Circuit::execute`] an unpredictable
    /// branch: the AES-128 Bristol Fashion circuit changes gate type every third
    /// gate, and the resulting mispredictions cost more than the AND gates it
    /// saves relative to the Bristol Format circuit. Since gates at the same
    /// depth cannot depend on one another, we are free to group them by type.
    ///
    /// This renumbers the circuit's wires, since a gate's output wire is implied
    /// by its position; the circuit's `output_refs` are updated to match.
    fn batch_gates_by_type(&mut self) {
        /// Sort key placing gates of the same depth next to each other, grouped
        /// by type.
        fn key(depth: u32, gate: &BinaryGate) -> usize {
            let typ = match gate {
                BinaryGate::Xor { .. } => 0,
                BinaryGate::And { .. } => 1,
                BinaryGate::Inv { .. } => 2,
            };
            depth as usize * N_GATE_TYPES + typ
        }

        // The depth of each wire: input wires have depth zero, and a gate's
        // output wire is one deeper than its deepest input wire.
        let mut depths = vec![0u32; self.ninputs + self.gates.len()];
        let mut max_depth = 0;
        for (i, gate) in self.gates.iter().enumerate() {
            let depth = match *gate {
                BinaryGate::Xor { xref, yref } | BinaryGate::And { xref, yref } => {
                    depths[xref as usize].max(depths[yref as usize])
                }
                BinaryGate::Inv { xref } => depths[xref as usize],
            } + 1;
            depths[self.ninputs + i] = depth;
            max_depth = max_depth.max(depth);
        }

        // Sort the gates by `(depth, gate type)`.
        let mut offsets = vec![0usize; (max_depth as usize + 1) * N_GATE_TYPES + 1];
        for (i, gate) in self.gates.iter().enumerate() {
            offsets[key(depths[self.ninputs + i], gate) + 1] += 1;
        }
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let mut order = vec![0usize; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let offset = &mut offsets[key(depths[self.ninputs + i], gate)];
            order[*offset] = i;
            *offset += 1;
        }

        // Rebuild the gates in the new order, mapping each wire to its new
        // index. A gate's inputs are strictly shallower than the gate itself,
        // and so have already been remapped by the time we reach it.
        let mut new_wire = vec![0u32; depths.len()];
        for (i, wire) in new_wire.iter_mut().enumerate().take(self.ninputs) {
            *wire = i as u32;
        }
        let mut gates = Vec::with_capacity(self.gates.len());
        for (new, &old) in order.iter().enumerate() {
            let remap = |wire: u32| new_wire[wire as usize];
            gates.push(match self.gates[old] {
                BinaryGate::Xor { xref, yref } => BinaryGate::Xor {
                    xref: remap(xref),
                    yref: remap(yref),
                },
                BinaryGate::And { xref, yref } => BinaryGate::And {
                    xref: remap(xref),
                    yref: remap(yref),
                },
                BinaryGate::Inv { xref } => BinaryGate::Inv { xref: remap(xref) },
            });
            new_wire[self.ninputs + old] = (self.ninputs + new) as u32;
        }
        self.gates = gates;
        self.output_refs = self
            .output_refs
            .iter()
            .map(|&wire| new_wire[wire as usize])
            .collect();
    }
}
