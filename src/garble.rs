use circuit::{Circuit, Gate};
use rand::Rng;
use wire::Wire;

use std::collections::HashMap;

type GarbledGate = Vec<Wire>;

pub struct Garbler {
    deltas     : HashMap<u8, Wire>,
    inputs     : Vec<Wire>,
    outputs    : Vec<Vec<Wire>>,
    rng        : Rng,
}

pub struct Evaluator {
    gates : Vec<GarbledGate>,
}

#[allow(non_snake_case)]
pub fn garble(c: &Circuit) -> (Garbler, Evaluator) {
    let mut gb = Garbler::new();

    let mut wires: Vec<Wire> = Vec::new();
    let mut gates: Vec<Vec<Wire>> = Vec::new();
    for i in 0..c.gates.len() {
        let q = c.moduli[i];
        let w = match c.gates[i] {
            Gate::Input { .. } => gb.input(q),

            Gate::Add { xref, yref } => wires[xref].plus(&wires[yref]),
            Gate::Sub { xref, yref } => wires[xref].minus(&wires[yref]),
            Gate::Cmul { xref, c }   => wires[xref].cmul(c),

            Gate::Proj { xref, ref tt, .. }  => {
                let X = wires[xref].clone();
                let (w,g) = gb.proj(&X, q, tt, i);
                gates.push(g);
                w
            }

            Gate::Yao { xref, yref, ref tt, .. } => {
                let X = wires[xref].clone();
                let Y = wires[yref].clone();
                let (w,g) = gb.yao(&X, &Y, q, tt, i);
                gates.push(g);
                w
            }
            Gate::HalfGate { xref, yref, .. }  => {
                let X = wires[xref].clone();
                let Y = wires[yref].clone();
                let (w,g) = gb.half_gate(&X, &Y, q, i);
                gates.push(g);
                w
            }
        };
        wires.push(w); // add the new zero-wire
    }
    for (i, &r) in c.output_refs.iter().enumerate() {
        let X = wires[r].clone();
        gb.output(&X, i);
    }

    (gb, Evaluator::new(gates))
}

#[allow(non_snake_case)]
impl Garbler {
    pub fn new() -> Self {
        Garbler {
            deltas: HashMap::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            rng: Rng::new(),
        }
    }

    fn delta(&mut self, q: u8) -> Wire {
        if !self.deltas.contains_key(&q) {
            let w = Wire::rand_delta(&mut self.rng, q);
            self.deltas.insert(q, w.clone());
            w
        } else {
            self.deltas[&q].clone()
        }
    }

    pub fn input(&mut self, q: u8) -> Wire {
        let w = Wire::rand(&mut self.rng, q);
        self.inputs.push(w.clone());
        w
    }

    pub fn output(&mut self, X: &Wire, output_num: usize) {
        let mut cts = Vec::new();
        let q = X.modulus();
        let ref D = self.delta(q);
        for k in 0..q {
            let t = output_tweak(output_num, k);
            cts.push(X.plus(&D.cmul(k)).hash(t, q));
        }
        self.outputs.push(cts);
    }

    pub fn proj(&mut self, A: &Wire, q_out: u8, tt: &Vec<u8>, gate_num: usize)
        -> (Wire, GarbledGate)
    {
        let q_in = A.modulus();
        // we have to fill in the vector in an unkonwn order because of the
        // color bits. Since some of the values in gate will be void
        // temporarily, we use Vec<Option<..>>
        let mut gate = vec![None; q_in as usize - 1];
        // input zero-wire
        let tao = A.color();
        // gate tweak
        let g = tweak(gate_num);
        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        let C = A.minus(&self.delta(q_in).cmul(tao))
                 .hash(g, q_out)
                 .negate()
                 .minus(&self.delta(q_out).cmul(tt[((q_in - tao) % q_in) as usize]));
        for x in 0..q_in {
            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 { continue }
            let A_ = A.plus(&self.delta(q_in).cmul(x));
            let C_ = C.plus(&self.delta(q_out).cmul(tt[x as usize]));
            let ct = A_.hash(g, q_out).plus(&C_);
            gate[ix-1] = Some(ct);
        }
        // unwrap the Option elems inside the Vec
        let gate = gate.into_iter().map(Option::unwrap).collect();
        (C, gate)
    }

    fn yao(&mut self, A: &Wire, B: &Wire, q: u8, tt: &Vec<Vec<u8>>, gate_num: usize)
        -> (Wire, GarbledGate)
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
        let ref B_delta = self.delta(ymod as u8);
        let C = A.minus(&self.delta(xmod as u8).cmul(A.color()))
                 .hash2(&B.minus(&B_delta.cmul(B.color())), g, q)
                 .negate()
                 .minus(&self.delta(q).cmul(sigma));
        for x in 0..xmod {
            let A_ = A.plus(&self.delta(xmod as u8).cmul(x as u8));
            for y in 0..ymod {
                let ix = ((A.color() as usize + x) % xmod) * ymod +
                         ((B.color() as usize + y) % ymod);
                if ix == 0 { continue }
                assert_eq!(gate[ix-1], None);
                let B_ = B.plus(&self.delta(ymod as u8).cmul(y as u8));
                let C_ = C.plus(&self.delta(q).cmul(tt[x][y]));
                let ct = A_.hash2(&B_, g, q).plus(&C_);
                gate[ix-1] = Some(ct);
            }
        }
        let gate = gate.into_iter().map(Option::unwrap).collect();
        (C, gate)
    }

    pub fn half_gate(&mut self, A: &Wire, B: &Wire, q: u8, gate_num: usize)
        -> (Wire, GarbledGate)
    {
        let mut gate = vec![None; 2 * q as usize - 2];
        let g = tweak(gate_num);

        let r = B.color(); // secret value known only to the garbler (ev knows r+b)

        let D = &self.delta(q); // delta for this modulus

        // X = -H(A+aD) - arD such that a + A.color == 0
        let alpha = q - A.color(); // alpha = -A.color
        let X = A.plus(&D.cmul(alpha)).hash(g,q).negate()
                 .plus(&D.cmul((alpha as u16 * r as u16 % q as u16) as u8));

        // Y = -H(B + bD) + brA
        let beta = q - B.color();
        let Y = B.plus(&D.cmul(beta)).hash(g,q).negate()
                 .plus(&A.cmul((beta + r) % q));

        for i in 0..q {
            // garbler's half-gate: outputs X-arD
            // G = H(A+aD) + X+a(-r)D = H(A+aD) + X-arD
            let a = i; // a: truth value of wire X
            let A_ = A.plus(&self.delta(q).cmul(a));
            if A_.color() != 0 {
                let tao = (a as u16 * (q - r) as u16 % q as u16) as u8;
                let G = A_.hash(g,q).plus(&X.plus(&D.cmul(tao)));
                gate[A_.color() as usize - 1] = Some(G);
            }

            // evaluator's half-gate: outputs Y+a(r+b)D
            // G = H(B+bD) + Y-(b+r)A
            let b = i; // b: truth value of wire A
            let B_ = B.plus(&D.cmul(b));
            if B_.color() != 0 {
                let G = B_.hash(g,q).plus(&Y.minus(&A.cmul((b+r)%q)));
                gate[(q + B_.color()) as usize - 2] = Some(G);
            }
        }
        let gate = gate.into_iter().map(Option::unwrap).collect();
        (X.plus(&Y), gate) // output zero wire
    }

    pub fn encode(&mut self, inputs: &[u8]) -> Vec<Wire> {
        assert_eq!(inputs.len(), self.inputs.len());
        let mut xs = Vec::new();
        for i in 0..inputs.len() {
            let x = inputs[i];
            let X = self.inputs[i].clone();
            let D = self.delta(X.modulus()).clone();
            xs.push(X.plus(&D.cmul(x)));
        }
        xs
    }

    pub fn decode(&self, ws: &[Wire]) -> Vec<u8> {
        assert_eq!(ws.len(), self.outputs.len());
        let mut outs = Vec::new();
        for i in 0..ws.len() {
            let q = ws[i].modulus();
            for k in 0..q {
                let h = ws[i].hash(output_tweak(i,k), q);
                if h == self.outputs[i][k as usize] {
                    outs.push(k);
                    break;
                }
            }
        }
        assert_eq!(ws.len(), outs.len());
        outs
    }
}

#[allow(non_snake_case)]
impl Evaluator {
    pub fn new(gates: Vec<GarbledGate>) -> Self {
        Evaluator { gates: gates }
    }

    pub fn size(&self) -> usize {
        let mut c = 0;
        for g in self.gates.iter() {
            c += g.len();
        }
        c
    }

    pub fn eval(&self, c: &Circuit, inputs: &[Wire]) -> Vec<Wire> {
        let mut wires: Vec<Wire> = Vec::new();
        for i in 0..c.gates.len() {
            let q = c.moduli[i];
            let w = match c.gates[i] {
                Gate::Input { id } => {
                    inputs[id].clone()
                }

                Gate::Add { xref, yref } => {
                    wires[xref].plus(&wires[yref])
                }

                Gate::Sub { xref, yref } => {
                    wires[xref].minus(&wires[yref])
                }

                Gate::Cmul { xref, c } => {
                    wires[xref].cmul(c)
                }

                Gate::Proj { xref, id, .. } => {
                    let ref x = wires[xref];
                    if x.color() == 0 {
                        x.hash(i as u128, q).negate()
                    } else {
                        let ref ct = self.gates[id][x.color() as usize - 1];
                        ct.minus(&x.hash(i as u128, q))
                    }
                }

                Gate::Yao { xref, yref, id, .. } => {
                    let ref a = wires[xref];
                    let ref b = wires[yref];
                    let g = tweak(i);
                    if a.color() == 0 && b.color() == 0 {
                        a.hash2(&b, g, q).negate()
                    } else {
                        let ix = a.color() as usize * c.moduli[yref] as usize + b.color() as usize;
                        let ref ct = self.gates[id][ix - 1];
                        ct.minus(&a.hash2(&b, g, q))
                    }
                }

                Gate::HalfGate { xref, yref, id } => {
                    let g = tweak(i);

                    // garbler's half gate
                    let ref A = wires[xref];
                    let L = if A.color() == 0 {
                        A.hash(g,q).negate()
                    } else {
                        let ref ct_left = self.gates[id][A.color() as usize - 1];
                        ct_left.minus(&A.hash(g,q))
                    };

                    // evaluator's half gate
                    let ref B = wires[yref];
                    let R = if B.color() == 0 {
                        B.hash(g,q).negate()
                    } else {
                        let ref ct_right = self.gates[id][(q + B.color()) as usize - 2];
                        ct_right.minus(&B.hash(g,q))

                    };
                    L.plus(&R.plus(&A.cmul(B.color())))
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

fn output_tweak(i: usize, k: u8) -> u128 {
    let (left, _) = (i as u128).overflowing_shl(64);
    left + k as u128
}


#[cfg(test)]
mod tests {
    use circuit::{Circuit, Builder};
    use garble::garble;
    use rand::Rng;

    fn add_circ(modulus: u8) -> Circuit {
        let mut b = Builder::new();
        let x = b.input(modulus);
        let y = b.input(modulus);
        let z = b.add(x,y);
        b.output(z);
        b.finish()
    }

    fn sub_circ(modulus: u8) -> Circuit {
        let mut b = Builder::new();
        let x = b.input(modulus);
        let y = b.input(modulus);
        let z = b.sub(x,y);
        b.output(z);
        b.finish()
    }

    fn cmul_circ(modulus: u8) -> Circuit {
        let mut b = Builder::new();
        let x = b.input(modulus);
        let _ = b.input(modulus);
        let z = b.cmul(x, 2);
        b.output(z);
        b.finish()
    }

    fn proj_circ(modulus: u8) -> Circuit {
        let mut tab = Vec::new();
        for i in 0..modulus {
            tab.push((i + 1) % modulus);
        }
        let mut b = Builder::new();
        let x = b.input(modulus);
        let _ = b.input(modulus);
        let z = b.proj(x, modulus, tab);
        b.output(z);
        b.finish()
    }

    fn yao_circ(q: u8) -> Circuit {
        let mut b = Builder::new();
        let x = b.input(q);
        let y = b.input(q);
        let mut tt = Vec::new();
        for a in 0..q {
            let mut tt_ = Vec::new();
            for b in 0..q {
                tt_.push((a as u16 * b as u16 % q as u16) as u8);
            }
            tt.push(tt_);
        }
        let z = b.yao(x, y, q, tt);
        b.output(z);
        b.finish()
    }

    fn mul_dlog_circ(modulus: u8) -> Circuit {
        let mut b = Builder::new();
        let x = b.input(modulus);
        let y = b.input(modulus);
        let z = b.mul_dlog(&[x,y]);
        b.output(z);
        b.finish()
    }

    fn half_gate_circ(modulus: u8) -> Circuit {
        let mut b = Builder::new();
        let x = b.input(modulus);
        let y = b.input(modulus);
        let z = b.half_gate(x,y);
        b.output(z);
        b.finish()
    }

    fn test_garble_helper<F,G>(f: F, g: G)
        where F: Fn(u8) -> Circuit,
              G: Fn(u8, u8, u8) -> u8
    {
        let mut rng = Rng::new();
        let q = rng.gen_prime();
        let c = f(q);
        let (mut gb, ev) = garble(&c);
        for _ in 0..16 {
            let x = rng.gen_byte() % q;
            let y = rng.gen_byte() % q;
            let xs = gb.encode(&[x,y]);
            let ys = ev.eval(&c, &xs);
            println!("x={} y={} g(x,y)={} %{} ", x, y, g(x,y,q), q);
            assert_eq!(gb.decode(&ys)[0], g(x,y,q));
        }
    }

    #[test]
    fn add() {
        test_garble_helper(add_circ, |x,y,q| (x+y)%q);
    }

    #[test]
    fn sub() {
        test_garble_helper(sub_circ, |x,y,q| (x + q - y)%q);
    }

    #[test]
    fn cmul() {
        test_garble_helper(cmul_circ, |x,_,q| 2*x%q);
    }

    #[test]
    fn proj() {
        test_garble_helper(proj_circ, |x,_,q| (x+1) % q);
    }

    #[test]
    fn yao() {
        test_garble_helper(yao_circ, |x,y,q| ((x as usize * y as usize) % q as usize) as u8);
    }

    #[test]
    fn mul_dlog() {
        test_garble_helper(mul_dlog_circ, |x,y,q| (x as usize * y as usize % q as usize) as u8);
    }

    #[test]
    fn half_gate() {
        test_garble_helper(half_gate_circ, |x,y,q| (x as usize * y as usize % q as usize) as u8);
    }

    #[test]
    fn and_gate_fan_n() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + rng.gen_byte() % 127;
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.ands(&inps);
        b.output(z);
        let c = b.finish();
        let (mut gb, ev) = garble(&c);

        for _ in 0..16 {
            let mut inps: Vec<u8> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u8);
            }
            let xs = gb.encode(&inps);
            let ys = ev.eval(&c, &xs);
            assert_eq!(gb.decode(&ys)[0], c.eval(&inps)[0])
        }
    }
}
