use crate::secretsharing::{CorrectionSharing, LinearSharing, SecretSharing};
use rand::{CryptoRng, Rng};
use scuttlebutt::field::FiniteField;
use simple_arith_circuit::{Circuit, Op};

/// A trait for additional functionality for circuit execution needed by inferno.
pub(crate) trait CircuitEvaluator<F: FiniteField, const N: usize> {
    fn eval_secret_sharing<R: Rng + CryptoRng>(
        &self,
        inputs: &[SecretSharing<F, N>],
        xs: &mut Vec<SecretSharing<F, N>>,
        ys: &mut Vec<SecretSharing<F, N>>,
        zs: &mut Vec<SecretSharing<F, N>>,
        rngs: &mut [R; N],
    ) -> SecretSharing<F, N>;

    fn eval_trace(
        &self,
        inputs: &[CorrectionSharing<F, N>],
        mults: &[CorrectionSharing<F, N>],
    ) -> (Vec<CorrectionSharing<F, N>>, Vec<CorrectionSharing<F, N>>);
}

impl<F: FiniteField, const N: usize> CircuitEvaluator<F, N> for Circuit<F> {
    /// Evaluate the circuit on secret shared values, where `xs` and `ys` correspond to the input shares
    /// to multiplication gates, and `zs` corresponds to the output shares of the multiplication
    /// gates. The output is a secret shared value of the output wire.
    ///
    /// Note: This assumes that the circuit only has _one_ output wire!
    fn eval_secret_sharing<R: Rng + CryptoRng>(
        &self,
        inputs: &[SecretSharing<F, N>],
        xs: &mut Vec<SecretSharing<F, N>>,
        ys: &mut Vec<SecretSharing<F, N>>,
        zs: &mut Vec<SecretSharing<F, N>>,
        rngs: &mut [R; N],
    ) -> SecretSharing<F, N> {
        assert_eq!(inputs.len(), self.ninputs());
        assert_eq!(self.noutputs(), 1);

        let mut circuit: Vec<SecretSharing<F, N>> = Vec::with_capacity(self.nwires());

        for input in inputs {
            circuit.push(*input);
        }

        for op in self.iter() {
            let res = match *op {
                Op::Add(n, m) => circuit[n] + circuit[m],
                Op::Sub(n, m) => circuit[n] - circuit[m],
                Op::Mul(n, m) => {
                    let x = circuit[n].secret();
                    let y = circuit[m].secret();
                    let z = x * y;
                    let z_share = SecretSharing::<F, N>::new(z, rngs);
                    xs.push(circuit[n]);
                    ys.push(circuit[m]);
                    zs.push(z_share);
                    z_share
                }
                Op::Constant(f) => SecretSharing::<F, N>::new_non_random(f),
                Op::Copy(n) => circuit[n],
            };
            circuit.push(res);
        }

        let output = circuit.last().unwrap();
        *output
    }

    /// Evaluate an execution trace of the circuit, where `mults` denotes the sharings of multiplication
    /// gate outputs. The output is sharings of the _inputs_ to the multiplication gates.
    fn eval_trace(
        &self,
        inputs: &[CorrectionSharing<F, N>],
        mults: &[CorrectionSharing<F, N>],
    ) -> (Vec<CorrectionSharing<F, N>>, Vec<CorrectionSharing<F, N>>) {
        assert_eq!(inputs.len(), self.ninputs());
        assert_eq!(mults.len(), self.nmuls());

        let mut circuit: Vec<_> = Vec::with_capacity(self.nwires());
        let mut xs: Vec<_> = Vec::with_capacity(self.nmuls());
        let mut ys: Vec<_> = Vec::with_capacity(self.nmuls());

        for input in inputs {
            circuit.push(*input);
        }

        let mut index = 0;

        for op in self.iter() {
            let res = match *op {
                Op::Add(n, m) => circuit[n] + circuit[m],
                Op::Sub(n, m) => circuit[n] - circuit[m],
                Op::Mul(n, m) => {
                    let x = circuit[n];
                    let y = circuit[m];
                    xs.push(x);
                    ys.push(y);
                    let z = mults[index];
                    index += 1;
                    z
                }
                Op::Constant(f) => CorrectionSharing::new_non_random(f),
                Op::Copy(n) => circuit[n],
            };
            circuit.push(res);
        }
        (xs, ys)
    }
}
