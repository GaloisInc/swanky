use crate::error::{EvaluatorError, FancyError};
use crate::fancy::{Fancy, HasModulus};
use crate::util::{output_tweak, tweak, tweak2};
use crate::wire::Wire;
use scuttlebutt::{AbstractChannel, Block};

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator<C> {
    channel: C,
    current_gate: usize,
    pub(crate) output_cts: Vec<Vec<Block>>,
    pub(crate) output_wires: Vec<Wire>,
}

impl<C: AbstractChannel> Evaluator<C> {
    /// Create a new `Evaluator`.
    pub fn new(channel: C) -> Self {
        Evaluator {
            channel,
            current_gate: 0,
            output_cts: Vec::new(),
            output_wires: Vec::new(),
        }
    }

    /// Decode the output received during the Fancy computation.
    pub fn decode_output(&self) -> Result<Vec<u16>, EvaluatorError> {
        debug_assert_eq!(
            self.output_wires.len(),
            self.output_cts.len(),
            "got {} wires, but have {} output ciphertexts",
            self.output_wires.len(),
            self.output_cts.len()
        );

        let mut outs = Vec::with_capacity(self.output_wires.len());
        for i in 0..self.output_wires.len() {
            let q = self.output_wires[i].modulus();
            debug_assert_eq!(q as usize, self.output_cts[i].len());
            for k in 0..q {
                let h = self.output_wires[i].hash(output_tweak(i, k));
                if h == self.output_cts[i][k as usize] {
                    outs.push(k);
                    break;
                }
            }
        }
        if self.output_wires.len() != outs.len() {
            return Err(EvaluatorError::DecodingFailed);
        }
        Ok(outs)
    }

    /// The current non-free gate index of the garbling computation.
    #[inline]
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// Read a Wire from the reader.
    #[inline]
    pub fn read_wire(&mut self, modulus: u16) -> Result<Wire, EvaluatorError> {
        let block = self.channel.read_block()?;
        Ok(Wire::from_block(block, modulus))
    }
}

impl<C: AbstractChannel> Fancy for Evaluator<C> {
    type Item = Wire;
    type Error = EvaluatorError;

    #[inline]
    fn constant(&mut self, _: u16, q: u16) -> Result<Wire, EvaluatorError> {
        self.read_wire(q)
    }

    #[inline]
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }

    #[inline]
    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }

    #[inline]
    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Wire, EvaluatorError> {
        Ok(x.cmul(c))
    }

    #[inline]
    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Wire, EvaluatorError> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = q != qb;
        let ngates = q as usize + qb as usize - 2 + unequal as usize;
        let mut gate = Vec::with_capacity(ngates);
        {
            for _ in 0..ngates {
                let block = self.channel.read_block()?;
                gate.push(block);
            }
        }
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        // garbler's half gate
        let L = if A.color() == 0 {
            A.hashback(g, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_block(ct_left ^ A.hash(g), q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            B.hashback(g, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_block(ct_right ^ B.hash(g), q)
        };

        // hack for unequal mods
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }

    #[inline]
    fn proj(&mut self, x: &Wire, q: u16, _: Option<Vec<u16>>) -> Result<Wire, EvaluatorError> {
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for _ in 0..ngates {
            let block = self.channel.read_block()?;
            gate.push(block);
        }
        let t = tweak(self.current_gate());
        if x.color() == 0 {
            Ok(x.hashback(t, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_block(ct ^ x.hash(t), q))
        }
    }

    #[inline]
    fn output(&mut self, x: &Wire) -> Result<(), EvaluatorError> {
        let noutputs = x.modulus() as usize;
        let mut blocks = Vec::with_capacity(noutputs);
        for _ in 0..noutputs {
            let block = self.channel.read_block()?;
            blocks.push(block);
        }
        self.output_cts.push(blocks);
        self.output_wires.push(x.clone());
        Ok(())
    }
}
