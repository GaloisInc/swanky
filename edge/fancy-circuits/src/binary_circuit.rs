use fancy_traits::{Circuit, CircuitInputMapper, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

mod parser;

/// A binary circuit represented as a vector of gates.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryCircuit {
    gates: Vec<BinaryGate>,
    input_refs: Vec<usize>,
    output_refs: Vec<usize>,
}

impl<F: FancyBinary> Circuit<F> for BinaryCircuit {
    type Input = Vec<F::Item>;
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut cache = vec![F::Item::default(); self.gates.len() + self.input_refs.len()];
        for (input, idx) in inputs.into_iter().zip(self.input_refs.iter()) {
            cache[*idx] = input;
        }
        for gate in self.gates.iter() {
            let (idx, result) = match gate {
                BinaryGate::Inv { xref, out } => (out, backend.negate(&cache[*xref])),
                BinaryGate::Xor { xref, yref, out } => {
                    (out, backend.xor(&cache[*xref], &cache[*yref]))
                }
                BinaryGate::And { xref, yref, out } => {
                    (out, backend.and(&cache[*xref], &cache[*yref], channel)?)
                }
            };
            cache[*idx] = result;
        }
        let mut outputs = Vec::with_capacity(self.output_refs.len());
        for i in self.output_refs.iter() {
            outputs.push(cache[*i].clone());
        }
        Ok(outputs)
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for BinaryCircuit {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.input_refs.len());
        inputs
    }

    fn ninputs(&self) -> usize {
        self.input_refs.len()
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

/// Binary computation supported by fancy garbling.
#[derive(Clone, Debug, PartialEq)]
pub enum BinaryGate {
    /// XOR gate.
    Xor {
        /// Left input wire index.
        xref: usize,
        /// Right input wire index.
        yref: usize,
        /// Output wire index.
        out: usize,
    },
    /// AND gate.
    And {
        /// Left input wire index.
        xref: usize,
        /// Right input wire index.
        yref: usize,
        /// Output wire index.
        out: usize,
    },
    /// NOT gate.
    Inv {
        /// Input wire index.
        xref: usize,
        /// Output wire index.
        out: usize,
    },
}

impl std::fmt::Display for BinaryGate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Xor { xref, yref, out } => write!(f, "Xor ( {}, {}, {} )", xref, yref, out),
            Self::And { xref, yref, out } => write!(f, "And ( {}, {}, {} )", xref, yref, out),
            Self::Inv { xref, out } => write!(f, "Inv ( {}, {} )", xref, out),
        }
    }
}

impl BinaryCircuit {
    /// Construct a new empty [`BinaryCircuit`], allocating `ngates` of space to
    /// store gates if provided.
    pub fn new(ngates: Option<usize>) -> Self {
        let gates = if let Some(n) = ngates {
            Vec::with_capacity(n)
        } else {
            Vec::new()
        };
        Self {
            gates,
            input_refs: Vec::new(),
            output_refs: Vec::new(),
        }
    }
}
