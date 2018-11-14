use util::IterToVec;

use std::collections::HashMap;

// the lowest-level circuit description in Fancy Garbling
// consists of 4 gate types:
//     * input
//     * addition
//     * scalar multiplication
//     * projection gates
//
// TODO: this is a lie! we have many new kinds of gates...

pub type Ref = usize;
pub type Id = usize;

#[derive(Debug)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub gate_moduli: Vec<u16>,
    pub input_refs: Vec<Ref>,
    pub output_refs: Vec<Ref>,
    pub const_vals: Option<Vec<u16>>,
    pub num_nonfree_gates: usize,
}

#[derive(Debug)]
pub enum Gate {
    Input { id: Id },                                           // id is the input id
    Const { id: Id },                                           // id is the const id
    Add { xref: Ref, yref: Ref },
    Sub { xref: Ref, yref: Ref },
    Cmul { xref: Ref, c: u16 },
    Proj { xref: Ref, tt: Vec<u16>, id: Id },                   // id is the gate number
    Yao { xref: Ref, yref: Ref, tt: Vec<Vec<u16>>, id: Id },    // id is the gate number
    HalfGate { xref: Ref, yref: Ref, id: Id },                  // id is the gate number
}

impl Circuit {
    pub fn eval(&self, inputs: &[u16]) -> Vec<u16> {
        debug_assert_eq!(inputs.len(), self.ninputs(),
            "[circuit.eval] needed {} inputs but got {}!",
            self.ninputs(), inputs.len()
        );

        let mut cache = vec![0;self.gates.len()];
        for zref in 0..self.gates.len() {
            let q = self.gate_moduli[zref];
            let val = match self.gates[zref] {

                Gate::Input { id } => inputs[id],

                Gate::Const { id } => {
                    debug_assert!(id < self.const_vals.as_ref().map_or(0, |cs| cs.len()),
                            "[eval_full] not enough constants provided");
                    self.const_vals.as_ref().expect("no consts provided")[id]
                }

                Gate::Add { xref, yref } => (cache[xref] + cache[yref]) % q,
                Gate::Sub { xref, yref } => (cache[xref] + q - cache[yref]) % q,

                Gate::Cmul { xref, c } => cache[xref] * c % q,

                Gate::Proj { xref, ref tt, .. } => tt[cache[xref] as usize],

                Gate::Yao { xref, yref, ref tt, .. } =>
                    tt[cache[xref] as usize][cache[yref] as usize],

                Gate::HalfGate { xref, yref, .. } =>
                    (cache[xref] * cache[yref] % q),
            };
            cache[zref] = val;
        }
        self.output_refs.iter().map(|outref| cache[*outref]).collect()
    }

    pub fn ninputs(&self) -> usize { self.input_refs.len() }
    pub fn noutputs(&self) -> usize { self.output_refs.len() }
    pub fn modulus(&self, x: Ref) -> u16 { self.gate_moduli[x] }

    pub fn input_mod(&self, id: Id) -> u16 {
        let r = self.input_refs[id];
        self.gate_moduli[r]
    }

    pub fn clear_consts(&mut self) {
        self.const_vals = None;
    }
}

// Use a Builder to conveniently make a Circuit
pub struct Builder {
    next_ref: Ref,
    next_input_id: Id,
    const_map: HashMap<(u16,u16), Ref>,
    pub circ: Circuit,
}

impl Builder {
    pub fn new() -> Self {
        let c = Circuit {
            gates: Vec::new(),
            input_refs: Vec::new(),
            output_refs: Vec::new(),
            gate_moduli: Vec::new(),
            const_vals: Some(Vec::new()),
            num_nonfree_gates: 0,
        };
        Builder {
            next_ref: 0,
            next_input_id: 0,
            const_map: HashMap::new(),
            circ: c
        }
    }

    pub fn finish(self) -> Circuit {
        self.circ
    }

    pub fn borrow_circ(&self) -> &Circuit {
        &self.circ
    }

    pub fn modulus(&self, x:Ref) -> u16 {
        self.circ.modulus(x)
    }

    fn get_next_input_id(&mut self) -> Id {
        let id = self.next_input_id;
        self.next_input_id += 1;
        id
    }

    fn get_next_ciphertext_id(&mut self) -> Id {
        let id = self.circ.num_nonfree_gates;
        self.circ.num_nonfree_gates += 1;
        id
    }

    fn get_next_ref(&mut self) -> Ref {
        let x = self.next_ref;
        self.next_ref += 1;
        x
    }

    fn gate(&mut self, gate: Gate, modulus: u16) -> Ref {
        self.circ.gates.push(gate);
        self.circ.gate_moduli.push(modulus);
        self.get_next_ref()
    }

    pub fn input(&mut self, modulus: u16) -> Ref {
        let gate = Gate::Input { id: self.get_next_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.input_refs.push(r);
        r
    }

    pub fn inputs(&mut self, n: usize, modulus: u16) -> Vec<Ref> {
        (0..n).map(|_| self.input(modulus)).collect()
    }

    pub fn secret_constant(&mut self, val: u16, modulus: u16) -> Ref {
        let id = self.circ.const_vals.as_ref().map_or(0, |cs| cs.len());
        self.circ.const_vals.as_mut().map(|cs| cs.push(val));
        let gate = Gate::Const { id };
        self.gate(gate, modulus)
    }

    pub fn constant(&mut self, val: u16, modulus: u16) -> Ref {
        match self.const_map.get(&(val, modulus)) {
            Some(&r) => r,
            None => {
                let id = self.circ.const_vals.as_ref().map_or(0, |cs| cs.len());
                self.circ.const_vals.as_mut().map(|cs| cs.push(val));
                let gate = Gate::Const { id };
                let r = self.gate(gate, modulus);
                self.const_map.insert((val,modulus), r);
                r
            }
        }
    }

    pub fn output(&mut self, xref: Ref) {
        self.circ.output_refs.push(xref);
    }

    pub fn outputs(&mut self, xs: &[Ref]) {
        for &x in xs.iter() {
            self.output(x);
        }
    }

    pub fn add(&mut self, xref: Ref, yref: Ref) -> Ref {
        debug_assert!(xref < self.next_ref);
        debug_assert!(yref < self.next_ref);
        let xmod = self.circ.gate_moduli[xref];
        let ymod = self.circ.gate_moduli[yref];
        debug_assert!(xmod == ymod, "xmod={} ymod={}", xmod, ymod);
        let gate = Gate::Add { xref, yref };
        self.gate(gate, xmod)
    }

    pub fn sub(&mut self, xref: Ref, yref: Ref) -> Ref {
        debug_assert!(xref < self.next_ref);
        debug_assert!(yref < self.next_ref);
        let xmod = self.circ.gate_moduli[xref];
        let ymod = self.circ.gate_moduli[yref];
        debug_assert!(xmod == ymod);
        let gate = Gate::Sub { xref, yref };
        self.gate(gate, xmod)
    }

    pub fn cmul(&mut self, xref: Ref, c: u16) -> Ref {
        let q = self.modulus(xref);
        self.gate(Gate::Cmul { xref, c }, q)
    }

    pub fn add_many(&mut self, args: &[Ref]) -> Ref {
        debug_assert!(args.len() > 1);
        let mut z = args[0];
        for &x in args.iter().skip(1) {
            z = self.add(z, x);
        }
        z
    }

    pub fn proj(&mut self, xref: Ref, output_modulus: u16, tt: Vec<u16>) -> Ref {
        debug_assert_eq!(tt.len(), self.circ.gate_moduli[xref] as usize);
        debug_assert!(tt.iter().all(|&x| x < output_modulus),
            "not all xs were less than the output modulus! circuit.proj: tt={:?},
            output_modulus={}", tt, output_modulus);
        let q = output_modulus;
        let gate = Gate::Proj { xref, tt, id: self.get_next_ciphertext_id() };
        self.gate(gate, q)
    }

    // the classic yao binary gate, over mixed moduli!
    pub fn yao(&mut self, xref: Ref, yref: Ref, output_modulus: u16, tt: Vec<Vec<u16>>) -> Ref {
        debug_assert!(tt.iter().all(|ref inner| { inner.iter().all(|&x| x < output_modulus) }));
        let gate = Gate::Yao {
            xref,
            yref,
            tt,
            id: self.get_next_ciphertext_id()
        };
        self.gate(gate, output_modulus)
    }

    pub fn half_gate(&mut self, xref: Ref, yref: Ref) -> Ref {
        debug_assert_eq!(self.modulus(xref), self.modulus(yref));
        let gate = Gate::HalfGate {
            xref,
            yref,
            id: self.get_next_ciphertext_id(),
        };
        let q = self.modulus(xref);
        self.gate(gate, q)
    }

    /////////////////////////////////////
    // higher level circuit constructions

    pub fn xor(&mut self, x: Ref, y: Ref) -> Ref {
        debug_assert!(self.modulus(x) == 2);
        debug_assert!(self.modulus(y) == 2);
        self.add(x,y)
    }

    pub fn and(&mut self, x: Ref, y: Ref) -> Ref {
        debug_assert!(self.modulus(x) == 2);
        debug_assert!(self.modulus(y) == 2);
        self.half_gate(x,y)
    }

    pub fn and_many(&mut self, args: &[Ref]) -> Ref {
        debug_assert!(args.iter().all(|&x| self.modulus(x) == 2));
        // convert all the wires to base b+1
        let b = args.len() as u16;
        let wires: Vec<Ref> = args.iter().map(|&x| {
            self.mod_change(x, b+1)
        }).collect();
        self._and_many(&wires)
    }

    // assumes wires already are in base b+1
    pub fn _and_many(&mut self, args: &[Ref]) -> Ref {
        let b = args.len();
        debug_assert!(args.iter().all(|&x| self.modulus(x) == (b + 1) as u16));
        // add them together
        let z = self.add_many(&args);
        // decode the result in base 2
        let mut tab = vec![0;b+1];
        tab[b] = 1;
        self.proj(z, 2, tab)
    }

    pub fn or_many(&mut self, args: &[Ref]) -> Ref {
        debug_assert!(args.iter().all(|&x| self.modulus(x) == 2));
        // convert all the wires to base b+1
        let b = args.len();
        let wires: Vec<Ref> = args.iter().map(|&x| {
            self.proj(x, b as u16 + 1, vec![0,1])
        }).collect();

        // add them together
        let z = self.add_many(&wires);

        // decode the result in base 2
        let mut tab = vec![1;b+1];
        tab[0] = 0;
        self.proj(z, 2, tab)
    }

    pub fn mod_change(&mut self, xref: Ref, to_modulus: u16) -> Ref {
        let from_modulus = self.modulus(xref);
        if from_modulus == to_modulus {
            return xref;
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect();
        self.proj(xref, to_modulus, tab)
    }

    ////////////////////////////////////////////////////////////////////////////////
    // binary stuff

    pub fn fancy_addition(&mut self, xs: &[Vec<Ref>]) -> Vec<Ref> {
        let nargs = xs.len();
        let n = xs[0].len();
        debug_assert!(xs.iter().all(|x| x.len() == n));

        let mut digit_carry = None;
        let mut carry_carry = None;

        let mut max_carry = 0;

        let mut res = Vec::with_capacity(n);

        for i in 0..n {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x[i]).to_vec();

            // compute the digit -- easy
            let digit_sum = self.add_many(&ds);
            let digit = digit_carry.map_or(digit_sum, |d| self.add(digit_sum, d));

            if i < n-1 {
                // compute the carries
                let q = self.modulus(xs[0][i]);
                // max_carry currently contains the max carry from the previous iteration
                let max_val = nargs as u16 * (q-1) + max_carry;
                // now it is the max carry of this iteration
                max_carry = max_val / q;

                let modded_ds = ds.iter().map(|&d| {
                    self.mod_change(d, max_val+1)
                }).to_vec();
                let carry_sum = self.add_many(&modded_ds);
                // add in the carry from the previous iteration
                let carry = carry_carry.map_or(carry_sum, |c| self.add(carry_sum, c));

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = self.modulus(xs[0][i+1]);
                let tt = (0..=max_val).map(|i| (i / q) % next_mod).to_vec();
                digit_carry = Some(self.proj(carry, next_mod, tt));

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n-2 {
                    if max_carry < next_mod {
                        carry_carry = Some(self.mod_change(digit_carry.unwrap(), next_max_val + 1));
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).to_vec();
                        carry_carry = Some(self.proj(carry, next_max_val + 1, tt));
                    }
                } else {
                    // next digit is MSB so we dont need carry_carry
                    carry_carry = None;
                }

            } else {
                digit_carry = None;
                carry_carry = None;
            }

            res.push(digit);
        }

        res
    }


    pub fn addition(&mut self, xs: &[Ref], ys: &[Ref]) -> (Vec<Ref>, Ref) {
        debug_assert_eq!(xs.len(), ys.len());
        let cmod = self.modulus(xs[1]);
        let (mut z, mut c) = self.adder(xs[0], ys[0], None, cmod);
        let mut bs = vec![z];
        for i in 1..xs.len() {
            let cmod = self.modulus(*xs.get(i+1).unwrap_or(&xs[i]));
            let res = self.adder(xs[i], ys[i], Some(c), cmod);
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        (bs, c)
    }

    // avoids creating extra gates for the final carry
    pub fn addition_no_carry(&mut self, xs: &[Ref], ys: &[Ref]) -> Vec<Ref> {
        debug_assert_eq!(xs.len(), ys.len());

        let cmod = self.modulus(*xs.get(1).unwrap_or(&xs[0]));
        let (mut z, mut c) = self.adder(xs[0], ys[0], None, cmod);

        let mut bs = vec![z];
        for i in 1..xs.len()-1 {
            let cmod = self.modulus(*xs.get(i+1).unwrap_or(&xs[i]));
            let res = self.adder(xs[i], ys[i], Some(c), cmod);
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        z = self.add_many(&[*xs.last().unwrap(), *ys.last().unwrap(), c]);
        bs.push(z);
        bs
    }

    fn adder(&mut self, x: Ref, y: Ref, opt_c: Option<Ref>, carry_modulus: u16) -> (Ref, Ref) {
        let q = self.modulus(x);
        debug_assert_eq!(q, self.modulus(y));
        if q == 2 {
            if let Some(c) = opt_c {
                let z1 = self.xor(x,y);
                let z2 = self.xor(z1,c);
                let z3 = self.xor(x,c);
                let z4 = self.and(z1,z3);
                let mut carry = self.xor(z4,x);
                if carry_modulus != 2 {
                    carry = self.mod_change(carry, carry_modulus);
                }
                (z2, carry)
            } else {
                let z = self.xor(x,y);
                let mut carry = self.and(x,y);
                if carry_modulus != 2 {
                    carry = self.mod_change(carry, carry_modulus);
                }
                (z, carry)
            }
        } else {
            let (sum, qp, zp);

            if let Some(c) = opt_c {
                sum = self.add_many(&[x,y,c]);
                qp = 2*q;
            } else {
                sum = self.add(x,y);
                qp = 2*q-1;
            }

            let xp = self.mod_change(x, qp);
            let yp = self.mod_change(y, qp);

            if let Some(c) = opt_c {
                let cp = self.mod_change(c, qp);
                zp = self.add_many(&[xp, yp, cp]);
            } else {
                zp = self.add(xp, yp);
            }

            let tt = (0..qp).map(|x| u16::from(x >= q)).collect();
            let carry = self.proj(zp, carry_modulus, tt);
            (sum, carry)
        }
    }

    pub fn twos_complement(&mut self, xs: &[Ref]) -> Vec<Ref> {
        let not_xs = xs.iter().map(|&x| self.negate(x)).to_vec();
        let zero = self.constant(0,2);
        let mut const1 = vec![zero; xs.len()];
        const1[0] = self.constant(1,2);
        self.addition_no_carry(&not_xs, &const1)
    }

    pub fn negate(&mut self, x: Ref) -> Ref {
        debug_assert_eq!(self.modulus(x), 2);
        self.proj(x, 2, vec![1,0])
    }

    pub fn binary_subtraction(&mut self, xs: &[Ref], ys: &[Ref]) -> (Vec<Ref>, Ref) {
        let neg_ys = self.twos_complement(&ys);
        let (zs, c) = self.addition(&xs, &neg_ys);
        (zs, self.negate(c))
    }
}


#[cfg(test)]
mod tests {
    use circuit::Builder;
    use rand::Rng;
    use numbers;
    use util::IterToVec;

    #[test] // {{{ and_gate_fan_n
    fn and_gate_fan_n() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + (rng.gen_byte() % 200);
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.and_many(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(1, |acc, &x| x & acc);
            assert_eq!(c.eval(&inps)[0], res);
        }
    }
//}}}
    #[test] // {{{ or_gate_fan_n
    fn or_gate_fan_n() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + (rng.gen_byte() % 200);
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.or_many(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = c.eval(&inps)[0];
            if !(out == res) {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }
//}}}
    #[test] // {{{ half_gate
    fn half_gate() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let q = rng.gen_prime();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.half_gate(x,y);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            assert_eq!(c.eval(&vec![x,y])[0], x * y % q);
        }
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.input(p);
        let y = b.mod_change(x, q);
        let z = b.mod_change(y, p);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            assert_eq!(c.eval(&vec![x])[0], x % q);
        }
    }
//}}}
    #[test] // binary_addition {{{
    fn binary_addition() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let (zs, c) = b.addition(&xs, &ys);
        b.outputs(&zs);
        b.output(c);
        let c = b.finish();
        let mut rng = Rng::new();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = numbers::to_bits(x, 128);
            bits.extend(numbers::to_bits(y, 128).iter());
            let res = c.eval(&bits);
            let (z, carry) = x.overflowing_add(y);
            assert_eq!(numbers::u128_from_bits(&res[0..128]), z);
            assert_eq!(res[128], carry as u16);
        }
    }
//}}}
    #[test] // binary_addition_no_carry {{{
    fn binary_addition_no_carry() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let zs = b.addition_no_carry(&xs, &ys);
        b.outputs(&zs);
        let c = b.finish();
        let mut rng = Rng::new();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = numbers::to_bits(x, 128);
            bits.extend(numbers::to_bits(y, 128).iter());
            let res = c.eval(&bits);
            let (z, _carry) = x.overflowing_add(y);
            assert_eq!(numbers::u128_from_bits(&res[0..128]), z);
        }
    }

//}}}
    #[test] // binary_subtraction {{{
    fn binary_subtraction() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let (zs, c) = b.binary_subtraction(&xs, &ys);
        b.outputs(&zs);
        b.output(c);
        let circ = b.finish();
        let mut rng = Rng::new();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = numbers::to_bits(x, 128);
            bits.extend(numbers::to_bits(y, 128).iter());
            let res = circ.eval(&bits);
            let (z, carry) = x.overflowing_sub(y);
            assert_eq!(numbers::u128_from_bits(&res[0..128]), z);
            assert_eq!(res[128], carry as u16);
        }
    }
//}}}
    #[test] // add_many_mod_change {{{
    fn add_many_mod_change() {
        let mut b = Builder::new();
        let n = 113;
        let args = b.inputs(n, 2);
        let wires: Vec<_> = args.iter().map(|&x| {
            b.mod_change(x, n as u16 + 1)
        }).collect();
        let s = b.add_many(&wires);
        b.output(s);
        let c = &b.finish();

        let mut rng = Rng::new();
        for _ in 0..64 {
            let inps: Vec<u16> = (0..c.ninputs()).map(|i| {
                rng.gen_u16() % c.input_mod(i)
            }).collect();
            let s: u16 = inps.iter().sum();
            println!("{:?}, sum={}", inps, s);
            assert_eq!(c.eval(&inps)[0], s);
        }
    }
// }}}
    #[test] // base_4_addition_no_carry {{{
    fn base_q_addition_no_carry() {
        let mut b = Builder::new();
        let mut rng = Rng::new();

        let q = rng.gen_modulus();
        let n = 16;
        let xs = b.inputs(n,q);
        let ys = b.inputs(n,q);
        let zs = b.addition_no_carry(&xs, &ys);
        b.outputs(&zs);
        let c = b.finish();

        // test maximum overflow
        let Q = (q as u128).pow(n as u32);
        let x = Q - 1;
        let y = Q - 1;
        let mut ds = numbers::as_base_q(x,q,n);
        ds.extend(numbers::as_base_q(y,q,n).iter());
        let res = c.eval(&ds);
        let (z, _carry) = x.overflowing_add(y);
        assert_eq!(numbers::from_base_q(&res, q), z % Q);

        // test random values
        for _ in 0..64 {
            let Q = (q as u128).pow(n as u32);
            let x = rng.gen_u128() % Q;
            let y = rng.gen_u128() % Q;
            let mut ds = numbers::as_base_q(x,q,n);
            ds.extend(numbers::as_base_q(y,q,n).iter());
            let res = c.eval(&ds);
            let (z, _carry) = x.overflowing_add(y);
            assert_eq!(numbers::from_base_q(&res, q), z % Q);
        }
    }
//}}}
    #[test] // fancy_addition {{{
    fn fancy_addition() {
        let mut rng = Rng::new();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).to_vec();

        let mut b = Builder::new();
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).to_vec()
        }).to_vec();
        let zs = b.fancy_addition(&xs);
        b.outputs(&zs);
        let circ = b.finish();

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test maximum overflow
        let mut ds = Vec::new();
        for _ in 0..nargs {
            ds.extend(numbers::as_mixed_radix(Q-1, &mods).iter());
        }
        let res = circ.eval(&ds);
        assert_eq!(numbers::from_mixed_radix(&res,&mods), (Q-1)*(nargs as u128) % Q);

        // test random values
        for _ in 0..64 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(numbers::as_mixed_radix(x, &mods).iter());
            }
            let res = circ.eval(&ds);
            assert_eq!(numbers::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = Builder::new();
        let mut rng = Rng::new();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.input(q);
        let y = b.constant(c,q);
        let z = b.add(x,y);
        b.output(z);

        let circ = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let z = circ.eval(&[x]);
            assert_eq!(z[0], (x+c)%q);
        }
    }
//}}}

}
