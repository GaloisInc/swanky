use crate::circuit::{Circuit, Gate, Id};
use crate::wire::Wire;
use itertools::Itertools;
use rand::Rng;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;

type GarbledGate = Vec<u128>;

#[derive(Serialize, Deserialize)]
pub struct Encoder {
    inputs : Vec<Wire>,
    deltas : HashMap<u16,Wire>,
}

#[derive(Serialize, Deserialize)]
pub struct Decoder {
    outputs : Vec<Vec<u128>>
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Evaluator {
    gates  : Vec<GarbledGate>,
    consts : Vec<Wire>,
}

pub fn garble<R:Rng>(c: &Circuit, rng: &mut R) -> (Encoder, Decoder, Evaluator) {
    let mut deltas  = HashMap::new();
    let mut inputs  = Vec::new();
    let mut consts  = Vec::new();

    for &m in c.gate_moduli.iter().unique() {
        let w = Wire::rand_delta(rng, m);
        deltas.insert(m, w);
    }

    let mut wires: Vec<Wire> = Vec::with_capacity(c.gates.len());
    let mut gates: Vec<GarbledGate> = Vec::with_capacity(c.num_nonfree_gates);

    for i in 0..c.gates.len() {
        let q = c.modulus(i);
        let (w,g) = match c.gates[i] {
            Gate::Input { .. } => garble_input(q, rng, &mut inputs),
            Gate::Const { .. } => garble_constant(q, rng, &mut consts),

            Gate::Add { xref, yref } => (wires[xref].plus(&wires[yref]),  None),
            Gate::Sub { xref, yref } => (wires[xref].minus(&wires[yref]), None),
            Gate::Cmul { xref, c }   => (wires[xref].cmul(c),             None),

            Gate::Proj { xref, ref tt, .. }      => garble_projection(&wires[xref], q, tt, i, &deltas),
            Gate::Yao { xref, yref, ref tt, .. } => garble_yao(&wires[xref], &wires[yref], q, tt, i, &deltas),
            Gate::HalfGate { xref, yref, .. }    => garble_half_gate(&wires[xref], &wires[yref], i, &deltas, rng),
        };
        wires.push(w);
        if let Some(g) = g { gates.push(g) }
    }

    let outputs = c.output_refs.iter().enumerate().map(|(i, &r)| {
        garble_output(&wires[r], i, &deltas)
    }).collect();

    let cs = c.const_vals.as_ref().expect("constants needed!");
    let ev = Evaluator::new(gates, encode_consts(cs, &consts, &deltas));
    let en = Encoder::new(inputs, deltas);
    let de = Decoder::new(outputs);
    (en, de, ev)
}

fn garble_input<R:Rng>(q: u16, rng: &mut R, inputs: &mut Vec<Wire>)
    -> (Wire, Option<GarbledGate>)
{
    let w = Wire::rand(rng, q);
    inputs.push(w.clone());
    (w, None)
}

fn garble_constant<R:Rng>(q: u16, rng: &mut R, consts: &mut Vec<Wire>)
    -> (Wire, Option<GarbledGate>)
{
    let w = Wire::rand(rng, q);
    consts.push(w.clone());
    (w, None)
}

fn garble_output(X: &Wire, output_num: usize, deltas: &HashMap<u16,Wire>)
    -> Vec<u128>
{
    let mut cts = Vec::new();
    let q = X.modulus();
    let D = &deltas[&q];
    for k in 0..q {
        let t = output_tweak(output_num, k);
        cts.push(X.plus(&D.cmul(k)).hash(t));
    }
    cts
}

fn garble_projection(A: &Wire, q_out: u16, tt: &[u16], gate_num: usize, deltas: &HashMap<u16,Wire>)
    -> (Wire, Option<GarbledGate>)
{
    let q_in = A.modulus();
    // we have to fill in the vector in an unkonwn order because of the
    // color bits. Since some of the values in gate will be void
    // temporarily, we use Vec<Option<..>>
    let mut gate = vec![None; q_in as usize - 1];

    let tao = A.color();        // input zero-wire
    let g = tweak(gate_num);    // gate tweak

    let Din  = &deltas[&q_in];
    let Dout = &deltas[&q_out];

    // output zero-wire
    // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
    // let C = A.minus(&Din.cmul(tao))
    //             .hashback(g, q_out)
    //             .minus(&Dout.cmul(tt[((q_in - tao) % q_in) as usize]));
    let mut C = A.clone();
    C.plus_eq(&Din.cmul((q_in-tao) % q_in));
    C = C.hashback(g, q_out);
    C.plus_eq(&Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out));

    // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
    let C_precomputed = {
        let mut C_ = C.clone();
        (0..q_out).map(|x| {
            if x > 0 {
                C_.plus_eq(&Dout);
            }
            C_.as_u128()
        }).collect_vec()
    };

    let mut A_ = A.clone();
    for x in 0..q_in {
        if x > 0 {
            A_.plus_eq(&Din); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
        }

        let ix = (tao as usize + x as usize) % q_in as usize;
        if ix == 0 { continue }

        let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
        gate[ix - 1] = Some(ct);
    }

    // unwrap the Option elems inside the Vec
    let gate = gate.into_iter().map(Option::unwrap).collect();
    (C, Some(gate))
}

fn garble_yao(A: &Wire, B: &Wire, q: u16, tt: &[Vec<u16>], gate_num: usize, deltas: &HashMap<u16,Wire>)
    -> (Wire, Option<GarbledGate>)
{
    let xmod = A.modulus() as usize;
    let ymod = B.modulus() as usize;
    let mut gate = vec![None; xmod * ymod - 1];

    // gate tweak
    let g = tweak(gate_num);

    // sigma is the output truth value of the 0,0-colored wirelabels
    let sigma = tt[((xmod - A.color() as usize) % xmod) as usize]
                  [((ymod - B.color() as usize) % ymod) as usize];

    // we use the row reduction trick here
    let B_delta = &deltas[&(ymod as u16)];
    let C = A.minus(&deltas[&(xmod as u16)].cmul(A.color()))
                .hashback2(&B.minus(&B_delta.cmul(B.color())), g, q)
                .minus(&deltas[&q].cmul(sigma));

    for x in 0..xmod {
        let A_ = A.plus(&deltas[&(xmod as u16)].cmul(x as u16));
        for y in 0..ymod {
            let ix = ((A.color() as usize + x) % xmod) * ymod +
                     ((B.color() as usize + y) % ymod);
            if ix == 0 { continue }
            debug_assert_eq!(gate[ix-1], None);
            let B_ = B.plus(&deltas[&(ymod as u16)].cmul(y as u16));
            let C_ = C.plus(&deltas[&q].cmul(tt[x][y]));
            let ct = A_.hash2(&B_,g) ^ C_.as_u128();
            gate[ix-1] = Some(ct);
        }
    }
    let gate = gate.into_iter().map(Option::unwrap).collect();
    (C, Some(gate))
}

fn garble_half_gate<R: Rng>(A: &Wire, B: &Wire, gate_num: usize, deltas: &HashMap<u16,Wire>, rng: &mut R)
    -> (Wire, Option<GarbledGate>)
{
    let q = A.modulus();
    let qb = B.modulus();

    debug_assert!(q >= qb);

    let D = deltas[&q].clone();
    let Db = deltas[&qb].clone();

    let r;
    let mut gate = vec![None; q as usize + qb as usize - 2];

    // hack for unequal moduli
    if q != qb {
        // would need to pack minitable into more than one u128 to support qb > 8
        debug_assert!(qb <= 8, "qb capped at 8 for now!");

        r = rng.gen::<u16>() % q;
        let t = tweak2(gate_num as u64, 1);

        let mut minitable = vec![None; qb as usize];
        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_.plus_eq(&Db);
            }
            let new_color = (r+b) % q;
            let ct = (B_.hash(t) & 0xFFFF) ^ new_color as u128;
            minitable[B_.color() as usize] = Some(ct);
        }

        let mut packed = 0;
        for i in 0..qb as usize {
            packed += minitable[i].unwrap() << (16 * i);
        }
        gate.push(Some(packed));

    } else {
        r = B.color(); // secret value known only to the garbler (ev knows r+b)
    }

    let g = tweak2(gate_num as u64, 0);

    // X = H(A+aD) + arD such that a + A.color == 0
    let alpha = (q - A.color()) % q; // alpha = -A.color
    let X = A.plus(&D.cmul(alpha))
             .hashback(g,q)
             .plus(&D.cmul((alpha * r) % q));

    // Y = H(B + bD) + (b + r)A such that b + B.color == 0
    let beta = (qb - B.color()) % qb;
    let Y = B.plus(&Db.cmul(beta))
             .hashback(g,q)
             .plus(&A.cmul((beta + r) % q));

    // precompute a lookup table of X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
    //                            = X.plus(&D_cmul[((q - (a * r % q)) % q) as usize]).as_u128();
    let X_cmul = {
        let mut X_ = X.clone();
        (0..q).map(|x| {
            if x > 0 {
                X_.plus_eq(&D);
            }
            X_.as_u128()
        }).collect_vec()
    };

    let mut A_ = A.clone();
    for a in 0..q {
        if a > 0 {
            A_.plus_eq(&D);
        }
        // garbler's half-gate: outputs X-arD
        // G = H(A+aD) ^ X+a(-r)D = H(A+aD) ^ X-arD
        if A_.color() != 0 {
            // let G = A_.hash(g) ^ X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
            let G = A_.hash(g) ^ X_cmul[((q - (a * r % q)) % q) as usize];
            gate[A_.color() as usize - 1] = Some(G);
        }
    }

    // precompute a lookup table of Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
    //                            = Y.plus(&A_cmul[((q - ((b+r) % q)) % q) as usize]).as_u128();
    let Y_cmul = {
        let mut Y_ = Y.clone();
        (0..q).map(|x| {
            if x > 0 {
                Y_.plus_eq(&A);
            }
            Y_.as_u128()
        }).collect_vec()
    };

    let mut B_ = B.clone();
    for b in 0..qb {
        if b > 0 {
            B_.plus_eq(&Db)
        }
        // evaluator's half-gate: outputs Y-(b+r)D
        // G = H(B+bD) + Y-(b+r)A
        if B_.color() != 0 {
            // let G = B_.hash(g) ^ Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
            let G = B_.hash(g) ^ Y_cmul[((q - ((b+r) % q)) % q) as usize];
            gate[q as usize - 1 + B_.color() as usize - 1] = Some(G);
        }
    }

    let gate = gate.into_iter().map(Option::unwrap).collect();
    (X.plus(&Y), Some(gate)) // output zero wire
}

fn encode_consts(consts: &[u16], const_wires: &[Wire], deltas: &HashMap<u16,Wire>) -> Vec<Wire> {
    debug_assert_eq!(consts.len(), const_wires.len(), "[encode_consts] not enough consts!");
    let mut xs = Vec::new();
    for i in 0..consts.len() {
        let x = consts[i];
        let X = &const_wires[i];
        let D = &deltas[&X.modulus()];
        xs.push(X.plus(&D.cmul(x)));
    }
    xs
}

impl Encoder {
    pub fn new(inputs: Vec<Wire>, deltas: HashMap<u16,Wire>) -> Self {
        Encoder { inputs, deltas }
    }

    pub fn encode_input(&self, x: u16, id: Id) -> Wire {
        let X = &self.inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    pub fn encode(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.inputs.len());
        (0..inputs.len()).zip(inputs.iter()).map(|(id,&x)| {
            self.encode_input(x,id)
        }).collect()
    }
}

impl Decoder {
    pub fn new(outputs: Vec<Vec<u128>>) -> Self {
        Decoder { outputs }
    }

    pub fn decode(&self, ws: &[Wire]) -> Vec<u16> {
        debug_assert_eq!(ws.len(), self.outputs.len());
        let mut outs = Vec::new();
        for i in 0..ws.len() {
            let q = ws[i].modulus();
            for k in 0..q {
                let h = ws[i].hash(output_tweak(i,k));
                if h == self.outputs[i][k as usize] {
                    outs.push(k);
                    break;
                }
            }
        }
        debug_assert_eq!(ws.len(), outs.len(), "decoding failed");
        outs
    }
}

impl Evaluator {
    pub fn new(gates: Vec<GarbledGate>, consts: Vec<Wire>) -> Self {
        Evaluator { gates, consts }
    }

    pub fn size(&self) -> usize {
        let mut c = self.consts.len();
        for g in self.gates.iter() {
            c += g.len();
        }
        c
    }

    pub fn eval(&self, c: &Circuit, inputs: &[Wire]) -> Vec<Wire> {
        let mut wires: Vec<Wire> = Vec::new();
        for i in 0..c.gates.len() {
            let q = c.modulus(i);
            let w = match c.gates[i] {

                Gate::Input { id }       => inputs[id].clone(),
                Gate::Const { id, .. }   => self.consts[id].clone(),
                Gate::Add { xref, yref } => wires[xref].plus(&wires[yref]),
                Gate::Sub { xref, yref } => wires[xref].minus(&wires[yref]),
                Gate::Cmul { xref, c }   => wires[xref].cmul(c),

                Gate::Proj { xref, id, .. } => {
                    let x = &wires[xref];
                    if x.color() == 0 {
                        x.hashback(i as u128, q)
                    } else {
                        let ct = self.gates[id][x.color() as usize - 1];
                        Wire::from_u128(ct ^ x.hash(i as u128), q)
                    }
                }

                Gate::Yao { xref, yref, id, .. } => {
                    let a = &wires[xref];
                    let b = &wires[yref];
                    if a.color() == 0 && b.color() == 0 {
                        a.hashback2(&b, tweak(i), q)
                    } else {
                        let ix = a.color() as usize * c.modulus(yref) as usize + b.color() as usize;
                        let ct = self.gates[id][ix - 1];
                        Wire::from_u128(ct ^ a.hash2(&b, tweak(i)), q)
                    }
                }

                Gate::HalfGate { xref, yref, id } => {
                    let g = tweak2(i as u64, 0);

                    // garbler's half gate
                    let A = &wires[xref];
                    let L = if A.color() == 0 {
                        A.hashback(g,q)
                    } else {
                        let ct_left = self.gates[id][A.color() as usize - 1];
                        Wire::from_u128(ct_left ^ A.hash(g), q)
                    };

                    // evaluator's half gate
                    let B = &wires[yref];
                    let R = if B.color() == 0 {
                        B.hashback(g,q)
                    } else {
                        let ct_right = self.gates[id][(q + B.color()) as usize - 2];
                        Wire::from_u128(ct_right ^ B.hash(g), q)
                    };

                    // hack for unequal mods
                    let new_b_color = if c.modulus(xref) != c.modulus(yref) {
                        let minitable = *self.gates[id].last().unwrap();
                        let ct = minitable >> (B.color() * 16);
                        let pt = B.hash(tweak2(i as u64, 1)) ^ ct;
                        pt as u16
                    } else {
                        B.color()
                    };

                    L.plus(&R.plus(&A.cmul(new_b_color)))
                }
            };
            wires.push(w);
        }

        c.output_refs.iter().map(|&r| {
            wires[r].clone()
        }).collect()
    }
}


fn tweak(i: usize) -> u128 {
    i as u128
}
fn tweak2(i: u64, j: u64) -> u128 {
    ((i as u128) << 64) + j as u128
}

fn output_tweak(i: usize, k: u16) -> u128 {
    let (left, _) = (i as u128).overflowing_shl(64);
    left + k as u128
}

////////////////////////////////////////////////////////////////////////////////
// serialization

impl Encoder {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Encoder")
    }
    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Encoder from bytes"))
    }
}

impl Decoder {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Decoder")
    }
    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Decoder from bytes"))
    }
}

impl Evaluator {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Evaluator")
    }
    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Evaluator from bytes"))
    }
}


////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Builder};
    use crate::numbers;
    use crate::util::RngExt;
    use rand::thread_rng;
    use itertools::Itertools;

    // helper {{{
    fn garble_test_helper<F>(f: F)
        where F: Fn(u16) -> Circuit
    {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let c = &f(q);
            let (en, de, ev) = garble(&c, &mut rng);
            println!("number of ciphertexts for mod {}: {}", q, ev.size());
            for _ in 0..16 {
                let inps = (0..c.ninputs()).map(|i| { rng.gen_u16() % c.input_mod(i) }).collect_vec();
                let xs = &en.encode(&inps);
                let ys = &ev.eval(c, xs);
                let decoded = de.decode(ys)[0];
                let should_be = c.eval(&inps)[0];
                if decoded != should_be {
                    println!("inp={:?} q={} got={} should_be={}", inps, q, decoded, should_be);
                    panic!("failed test!");
                }
            }
        }
    }
//}}}
    #[test] // add {{{
    fn add() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.add(x,y);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let xs = b.inputs(16, q);
            let z = b.add_many(&xs);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // or_many {{{
    fn or_many() {
        garble_test_helper(|_| {
            let mut b = Builder::new();
            let xs = b.inputs(16, 2);
            let z = b.or_many(&xs);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // and_many {{{
    fn and_many() {
        garble_test_helper(|_| {
            let mut b = Builder::new();
            let xs = b.inputs(16, 2);
            let z = b.and_many(&xs);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // sub {{{
    fn sub() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.sub(x,y);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let _ = b.input(q);
            let z;
            if q > 2 {
                z = b.cmul(x, 2);
            } else {
                z = b.cmul(x, 1);
            }
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // proj_cycle {{{
    fn proj_cycle() {
        garble_test_helper(|q| {
            let mut tab = Vec::new();
            for i in 0..q {
                tab.push((i + 1) % q);
            }
            let mut b = Builder::new();
            let x = b.input(q);
            let _ = b.input(q);
            let z = b.proj(x, q, tab);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // proj_rand {{{
    fn proj_rand() {
        garble_test_helper(|q| {
            let mut rng = thread_rng();
            let mut tab = Vec::new();
            for _ in 0..q {
                tab.push(rng.gen_u16() % q);
            }
            let mut b = Builder::new();
            let x = b.input(q);
            let _ = b.input(q);
            let z = b.proj(x, q, tab);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let z = b.mod_change(x,q*2);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // yao {{{
    fn yao() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(q);
            let mut tt = Vec::new();
            for a in 0..q {
                let mut tt_ = Vec::new();
                for b in 0..q {
                    tt_.push(a * b % q);
                }
                tt.push(tt_);
            }
            let z = b.yao(x, y, q, tt);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.half_gate(x,y);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // half_gate_unequal_mods {{{
    fn half_gate_unequal_mods() {
        for q in 3..16 {
            let ymod = 2 + thread_rng().gen_u16() % 6; // lower mod is capped at 8 for now
            println!("\nTESTING MOD q={} ymod={}", q, ymod);

            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(ymod);
            let z = b.half_gate(x,y);
            b.output(z);
            let c = b.finish();

            let (en, de, ev) = garble(&c, &mut thread_rng());

            let mut fail = false;
            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x,y);
                    let xs = &en.encode(&[x,y]);
                    let ys = &ev.eval(&c, xs);
                    let decoded = de.decode(ys)[0];
                    let should_be = c.eval(&[x,y])[0];
                    if decoded != should_be {
                        println!("FAILED inp={:?} q={} got={} should_be={}", [x,y], q, decoded, should_be);
                        fail = true;
                    } else {
                        // println!("SUCCEEDED inp={:?} q={} got={} should_be={}", [x,y], q, decoded, should_be);
                    }
                }
            }
            if fail {
                panic!("failed!")
            }
        }
    }
//}}}
    #[test] // base_q_addition_no_carry {{{
    fn base_q_addition_no_carry() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let n = 16;
            let xs = b.inputs(n,q);
            let ys = b.inputs(n,q);
            let zs = b.addition_no_carry(&xs, &ys);
            b.outputs(&zs);
            b.finish()
        });
    }
//}}}
    #[test] // fancy_addition {{{
    fn fancy_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();
        // let nargs = 97;
        // let mods = [37,10,10,54,100,51,17];

        let mut b = Builder::new();
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).collect_vec()
        }).collect_vec();
        let zs = b.fancy_addition(&xs);
        b.outputs(&zs);
        let circ = b.finish();

        let (en, de, ev) = garble(&circ, &mut rng);
        println!("mods={:?} nargs={} size={}", mods, nargs, ev.size());

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test random values
        for _ in 0..16 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(numbers::as_mixed_radix(x, &mods).iter());
            }
            let X = en.encode(&ds);
            let Y = ev.eval(&circ, &X);
            let res = de.decode(&Y);
            assert_eq!(numbers::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = Builder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.input(q);
        let y = b.constant(c,q);
        let z = b.add(x,y);
        b.output(z);

        let circ = b.finish();
        let (en, de, ev) = garble(&circ, &mut rng);

        for _ in 0..64 {
            let x = rng.gen_u16() % q;

            assert_eq!(circ.eval(&[x])[0], (x+c)%q, "plaintext");

            let X = en.encode(&[x]);
            let Y = ev.eval(&circ, &X);
            assert_eq!(de.decode(&Y)[0], (x+c)%q, "garbled");
        }
    }
//}}}
    #[test] // serialize_evaluator {{{
    fn serialize_evaluator() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();
        // let nargs = 97;
        // let mods = [37,10,10,54,100,51,17];

        let mut b = Builder::new();
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).collect_vec()
        }).collect_vec();
        let zs = b.fancy_addition(&xs);
        b.outputs(&zs);
        let circ = b.finish();

        let (_, _, ev) = garble(&circ, &mut rng);

        assert_eq!(ev, Evaluator::from_bytes(&ev.to_bytes()).unwrap());
    }
//}}}
}
