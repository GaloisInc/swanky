use scuttlebutt::field::FiniteField;

#[cfg(feature = "serde")]
use crate::serialization::serde_index;

// Type denoting a wire index.
pub(crate) type Index = usize;

/// Gate operations, where the operation arguments correspond to _wire_ indices.
/// Results are always stored in the next available register.
///
/// Note that _wire_ indices include the inputs. That is,
/// `Add(5, 6)` does _not_ mean "add the output wires of ops at indices 5 and 6", but
/// rather, assuming there are `N` inputs, "add the output wires of ops at indices 5-N
/// and 6-N".
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Op<F: FiniteField> {
    /// Add two elements
    Add(
        #[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index,
        #[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index,
    ),
    /// Multiply two elements
    Mul(
        #[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index,
        #[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index,
    ),
    /// Subtract the first element from the second
    Sub(
        #[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index,
        #[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index,
    ),
    /// Load a constant value
    Constant(#[cfg_attr(feature = "serde", serde(bound = ""))] F),
    /// Copy an element
    Copy(#[cfg_attr(feature = "serde", serde(with = "serde_index"))] Index),
}

/// The circuit, represented as a vector of `Op`s.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Circuit<F: FiniteField> {
    /// The circuit operations.
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    pub(crate) ops: Vec<Op<F>>,
    /// The number of inputs.
    pub(crate) ninputs: usize,
    /// The number of outputs.
    pub(crate) noutputs: usize,
    /// The number of multiplication operations.
    pub(crate) nmuls: usize,
}

impl<F: FiniteField> Circuit<F> {
    /// Creates a new `Circuit` with `ninputs` input wires, `noutputs` output wires,
    /// and a vector of operations `ops`.
    ///
    /// # Panics
    ///
    /// Panics if the number of outputs is greater than the number of operations.
    pub fn new(ninputs: usize, noutputs: usize, ops: Vec<Op<F>>) -> Self {
        if noutputs > ops.len() {
            panic!("Number of outputs greater than number of operations!");
        }
        let nmuls = ops.iter().filter(|op| matches!(op, Op::Mul(_, _))).count();
        Self {
            ops,
            ninputs,
            noutputs,
            nmuls,
        }
    }

    /// Returns the number of inputs.
    pub fn ninputs(&self) -> usize {
        self.ninputs
    }

    /// Returns the number of outputs.
    pub fn noutputs(&self) -> usize {
        self.noutputs
    }

    /// Returns the number of multiplication gates.
    pub fn nmuls(&self) -> usize {
        self.nmuls
    }

    /// Returns the number of non-multiplication gates.
    pub fn nnonmuls(&self) -> usize {
        self.ops.len() - self.nmuls()
    }

    /// Returns the number of wires. This is equal to the number of operations plus
    /// the number of inputs.
    pub fn nwires(&self) -> usize {
        self.ops.len() + self.ninputs()
    }

    /// Evaluates a circuit on an input, returning the output wires.
    /// The `wires` vector will be filled in with all the intermediate
    /// circuit computations.
    ///
    /// # Errors
    ///
    /// This errors out if the number of inputs provided is not equal to the number
    /// of inputs the circuit expects.
    pub fn eval<'a>(&self, inputs: &[F], wires: &'a mut Vec<F>) -> &'a [F] {
        assert_eq!(inputs.len(), self.ninputs);

        wires.resize(self.nwires(), F::ZERO);
        wires.clear();
        for input in inputs {
            wires.push(*input);
        }

        for op in &self.ops {
            let res = match *op {
                Op::Add(n, m) => wires[n] + wires[m],
                Op::Mul(n, m) => wires[n] * wires[m],
                Op::Sub(n, m) => wires[n] - wires[m],
                Op::Constant(f) => f,
                Op::Copy(n) => wires[n],
            };
            wires.push(res);
        }
        &wires[wires.len() - self.noutputs..wires.len()]
    }

    // Extends a circuit with operation `op`, returning the index of the new operation
    // within the `ops` vector.
    pub(crate) fn push(&mut self, op: Op<F>) -> usize {
        let index = self.ops.len();
        self.ops.push(op);
        if matches!(op, Op::Mul(_, _)) {
            self.nmuls += 1;
        }
        index
    }
}

// Deref implementation so that we can iterate over the vector of operations when calling `self.iter()`.
impl<F: FiniteField> std::ops::Deref for Circuit<F> {
    type Target = Vec<Op<F>>;

    fn deref(&self) -> &Self::Target {
        &self.ops
    }
}
