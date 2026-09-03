use fancy_traits::{Circuit, CircuitInputMapper, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

mod parser;

/// Static representation of binary computation supported by fancy garbling.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryCircuit {
    pub(crate) gates: Vec<BinaryGate>,
    pub(crate) input_refs: Vec<usize>,
    pub(crate) const_refs: Vec<usize>,
    pub(crate) output_refs: Vec<usize>,
    pub(crate) num_nonfree_gates: usize,
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
        self.eval_to_wirelabels(backend, &inputs, channel)
    }
}

impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for BinaryCircuit {
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
///
/// `id` represents the gate number. `out` gives the output wire index; if `out
/// = None`, then we use the gate index as the output wire index.
#[derive(Clone, Debug, PartialEq)]
pub enum BinaryGate {
    /// Input value
    Input {
        /// Gate number
        id: usize,
    },
    /// Constant value
    Constant {
        /// Value of constant
        val: u16,
    },

    /// Xor gate
    Xor {
        /// Reference to input 1
        xref: usize,

        /// Reference to input 2
        yref: usize,

        /// Output wire index
        out: Option<usize>,
    },
    /// And gate
    And {
        /// Reference to input 1
        xref: usize,

        /// Reference to input 2
        yref: usize,

        /// Gate number
        id: usize,

        /// Output wire index
        out: Option<usize>,
    },
    /// Not gate
    Inv {
        /// Reference to input
        xref: usize,

        /// Output wire index
        out: Option<usize>,
    },
}

impl std::fmt::Display for BinaryGate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Input { id } => write!(f, "Input {}", id),
            Self::Constant { val } => write!(f, "Constant {}", val),
            Self::Xor { xref, yref, out } => write!(f, "Xor ( {}, {}, {:?} )", xref, yref, out),
            Self::And {
                xref,
                yref,
                id,
                out,
            } => write!(f, "And ( {}, {}, {}, {:?} )", xref, yref, id, out),
            Self::Inv { xref, out } => write!(f, "Inv ( {}, {:?} )", xref, out),
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
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            num_nonfree_gates: 0,
        }
    }

    fn eval_to_wirelabels<F: FancyBinary + FancyBinaryConstant>(
        &self,
        f: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<F::Item>> {
        let mut cache: Vec<Option<F::Item>> = vec![None; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let (zref_, val) = match *gate {
                BinaryGate::Input { id } => (None, inputs[id].clone()),
                BinaryGate::Constant { val } => (None, f.constant(F2::from(val != 0))),
                BinaryGate::Inv { xref, out } => (out, f.negate(cache[xref].as_ref().unwrap())),
                BinaryGate::Xor { xref, yref, out } => (
                    out,
                    f.xor(cache[xref].as_ref().unwrap(), cache[yref].as_ref().unwrap()),
                ),
                BinaryGate::And {
                    xref, yref, out, ..
                } => (
                    out,
                    f.and(
                        cache[xref].as_ref().unwrap(),
                        cache[yref].as_ref().unwrap(),
                        channel,
                    )?,
                ),
            };
            cache[zref_.unwrap_or(i)] = Some(val);
        }
        let mut outputs = Vec::with_capacity(self.output_refs.len());
        for r in self.output_refs.iter() {
            let wirelabel = cache[*r].as_ref().unwrap();
            outputs.push(wirelabel.clone());
        }
        Ok(outputs)
    }
}
