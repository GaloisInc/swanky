use itertools::Itertools;

use fancy_garbling::circuit::crt::CrtBundler;
use fancy_garbling::circuit::{Builder, Ref, Circuit};
use fancy_garbling::numbers;

use util;

pub struct NeuralNet {
    pub weights: Vec<Vec<Vec<i32>>>,
    pub biases: Vec<Vec<i32>>,
    pub topology: Vec<usize>,
}

impl NeuralNet {
    pub fn weight(&self, layer: usize, i: usize, j: usize) -> i32 {
        self.weights[layer][i][j]
    }

    pub fn bias(&self, layer: usize, j: usize) -> i32 {
        self.biases[layer][j]
    }

    pub fn from_dinn_file(weights_file: &str, biases_file: &str, topology: &[usize]) -> Self {
        let mut lines = util::get_lines(weights_file);
        let mut weights = Vec::with_capacity(topology.len()-1);
        for layer in 0..topology.len()-1 {
            let nin  = topology[layer];
            let nout = topology[layer+1];
            weights.push(Vec::with_capacity(nin));
            for i in 0..nin {
                weights[layer].push(Vec::with_capacity(nout));
                for _ in 0..nout {
                    let l = lines.next().expect("no more lines").expect("couldnt read a line");
                    let w = l.parse().expect("couldnt parse");
                    weights[layer][i].push(w);
                }
            }
        }

        let mut lines = util::get_lines(biases_file);
        let mut biases = Vec::with_capacity(topology.len()-1);
        for layer in 0..topology.len()-1 {
            let nout = topology[layer+1];
            biases.push(Vec::with_capacity(nout));
            for _ in 0..nout {
                let l = lines.next().expect("no more lines").expect("couldnt read a line");
                let w = l.parse().expect("couldnt parse");
                biases[layer].push(w);
            }
        }
        Self { weights, biases, topology: topology.to_vec() }
    }
}

////////////////////////////////////////////////////////////////////////////////
// circuit creation


pub fn build_circuit(q: u128, nn: &NeuralNet, secret_weights: bool) -> CrtBundler {
    let mut b = CrtBundler::new();
    let nn_inputs = b.inputs(q, nn.topology[0]);

    let mut layer_outputs = Vec::new();
    let mut layer_inputs;

    for layer in 0..nn.topology.len()-1 {
        if layer == 0 {
            layer_inputs = nn_inputs.clone();
        } else {
            layer_inputs  = layer_outputs;
            layer_outputs = Vec::new();
        }

        let nin  = nn.topology[layer];
        let nout = nn.topology[layer+1];

        for j in 0..nout {
            let bias = util::to_mod_q(q, nn.bias(layer,j));
            let mut x = b.secret_constant(bias, q);
            for i in 0..nin {
                let y;
                let weight = util::to_mod_q(q, nn.weight(layer,i,j));
                if secret_weights {
                    y = b.secret_cmul(layer_inputs[i], weight);
                } else {
                    y = b.cmul(layer_inputs[i], weight);
                }
                x = b.add(x, y);
            }
            layer_outputs.push(x);
        }

        if layer == 0 {
            layer_outputs = layer_outputs.into_iter().map(|x| {
                let ms = vec![3,4,54]; // exact for 5 primes
                // let ms = vec![5,5,6,50];  // exact for 6 primes
                b.sgn(x, &ms)
            }).collect();
        }
    }

    for out in layer_outputs.into_iter() {
        b.output(out);
    }
    b
}

pub fn build_boolean_circuit(nbits: usize, nn: &NeuralNet, secret_weights: bool) -> Circuit {
    let mut b = Builder::new();

    // binary inputs with 0 representing -1
    let nn_inputs = (0..nn.topology[0]).map(|_| b.input(2)).collect_vec();

    let mut layer_outputs = Vec::new();
    let mut layer_inputs;

    for layer in 0..nn.topology.len()-1 {
        if layer == 0 {
            layer_inputs = nn_inputs.clone();
        } else {
            layer_inputs  = layer_outputs;
            layer_outputs = Vec::new();
        }

        let nin  = nn.topology[layer];
        let nout = nn.topology[layer+1];

        let mut acc = Vec::new();

        for j in 0..nout {
            // map the bias values to binary consts
            let bias = util::i32_to_twos_complement(nn.bias(layer,j), nbits);
            let mut x = numbers::u128_to_bits(bias, nbits).into_iter().map(|bit| b.constant(bit,2)).collect_vec();
            for i in 0..nin {
                // hardcode the weights into the circuit
                let w = nn.weight(layer,i,j) as u128;
                let negw = util::twos_complement_negate(nn.weight(layer,i,j) as u128, nbits);

                let y = if secret_weights {
                    multiplex_secret_constants(&mut b, layer_inputs[i], w, negw, nbits)
                } else {
                    multiplex_constants(&mut b, layer_inputs[i], w, negw, nbits)
                };
                x = b.addition_no_carry(&x, &y);
            }
            acc.push(x);
        }

        if layer < nn.topology.len()-2 {
            layer_outputs = acc.into_iter().map(|x| x[nbits-1] ).collect();
        } else {
            for x in acc {
                b.outputs(&x);
            }
        }
    }

    b.finish()
}

fn multiplex_constants(b: &mut Builder, x: Ref, c1: u128, c2: u128, n: usize) -> Vec<Ref> {
    let c1_bs = numbers::to_bits(c1, n).into_iter().map(|x:u16| x > 0).collect_vec();
    let c2_bs = numbers::to_bits(c2, n).into_iter().map(|x:u16| x > 0).collect_vec();
    c1_bs.into_iter().zip(c2_bs.into_iter()).map(|(b1,b2)| mux_const_bits(b,x,b1,b2)).collect()
}

fn mux_const_bits(b: &mut Builder, x: Ref, b1: bool, b2: bool) -> Ref {
    if !b1 && b2 {
        x
    } else if b1 && !b2 {
        b.negate(x)
    } else if !b1 && !b2 {
        b.constant(0,2)
    } else {
        b.constant(1,2)
    }
}

fn multiplex_secret_constants(b: &mut Builder, x: Ref, c1: u128, c2: u128, n: usize) -> Vec<Ref> {
    let c1_bs = numbers::to_bits(c1, n).into_iter().map(|x:u16| x > 0).collect_vec();
    let c2_bs = numbers::to_bits(c2, n).into_iter().map(|x:u16| x > 0).collect_vec();
    c1_bs.into_iter().zip(c2_bs.into_iter()).map(|(b1,b2)| mux_secret_const_bits(b,x,b1,b2)).collect()
}

fn mux_secret_const_bits(b: &mut Builder, x: Ref, b1: bool, b2: bool) -> Ref {
    let s1 = b.secret_constant(b1 as u16, 2);
    let s2 = b.secret_constant(b2 as u16, 2);
    let nx = b.negate(x);
    let z1 = b.and(nx, s1);
    let z2 = b.and(x, s2);
    b.add(z1, z2)
}

#[cfg(test)]
mod dinn {
    use super::*;
    use fancy_garbling::circuit::Builder;
    use fancy_garbling::numbers;
    use fancy_garbling::util::RngExt;
    use rand;

    #[test]
    fn multiplex() {
        let mut rng = rand::thread_rng();

        let nbits = 16;
        let mask = (1 << nbits) - 1;

        let c1 = rng.gen_u128() & mask;
        let c2 = rng.gen_u128() & mask;

        let mut b = Builder::new();
        let x = b.input(2);
        let ys = multiplex_constants(&mut b, x, c1, c2, nbits);
        b.outputs(&ys);
        let circ = b.finish();

        let c1_bits = numbers::to_bits(c1, nbits);
        let c2_bits = numbers::to_bits(c2, nbits);

        assert_eq!(circ.eval(&[0]), c1_bits);
        assert_eq!(circ.eval(&[1]), c2_bits);
    }
}
