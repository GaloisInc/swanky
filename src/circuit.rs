use numbers::{dlog_truth_table, exp_truth_table};

// the lowest-level circuit description in Fancy Garbling
// consists of 4 gate types:
//     * input
//     * addition
//     * scalar multiplication
//     * projection gates

pub type Ref = usize;
pub type Id = usize;

#[derive(Debug)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub moduli: Vec<u8>,
    pub input_refs: Vec<Ref>,
    pub output_refs: Vec<Ref>,
}

#[derive(Debug)]
pub enum Gate {
    Input { id: Id },                                       // id is the input id
    Add { xref: Ref, yref: Ref },
    Sub { xref: Ref, yref: Ref },
    Cmul { xref: Ref, c: u8 },
    Proj { xref: Ref, tt: Vec<u8>, id: Id },             // id is the gate number
    Yao { xref: Ref, yref: Ref, tt: Vec<Vec<u8>>, id: Id }, // id is the gate number
    HalfGate { xref: Ref, yref: Ref, id: Id },              // id is the gate number
}

impl Circuit {
    pub fn eval(&self, inputs: &[u8]) -> Vec<u8> {
        let mut cache = vec![0;self.gates.len()];
        for zref in 0..self.gates.len() {
            let q = self.moduli[zref];
            let val = match self.gates[zref] {
                Gate::Input { id } =>
                    inputs[id],

                Gate::Add { xref, yref } =>
                    (cache[xref] + cache[yref]) % q,

                Gate::Sub { xref, yref } =>
                    ((cache[xref] as u16 + q as u16 - cache[yref] as u16 ) % q as u16) as u8,

                Gate::Cmul { xref, c } =>
                    (cache[xref] as u16 * c as u16 % q as u16) as u8,

                Gate::Proj { xref, ref tt, .. } =>
                    tt[cache[xref] as usize],

                Gate::Yao { xref, yref, ref tt, .. } =>
                    tt[cache[xref] as usize][cache[yref] as usize],

                Gate::HalfGate { xref, yref, .. } =>
                    (cache[xref] as u16 * cache[yref] as u16 % q as u16) as u8,
            };
            cache[zref] = val;
        }
        self.output_refs.iter().map(|outref| cache[*outref]).collect()
    }
}

// Use a Builder to conveniently make a Circuit
pub struct Builder {
    next_ref: Ref,
    next_input_id: Id,
    next_ciphertext_id: Id,
    pub circ: Circuit,
}

impl Builder {
    pub fn new() -> Self {
        let c = Circuit {
            gates: Vec::new(),
            input_refs: Vec::new(),
            output_refs: Vec::new(),
            moduli: Vec::new(),
        };
        Builder {
            next_ref: 0,
            next_input_id: 0,
            next_ciphertext_id: 0,
            circ: c
        }
    }

    pub fn finish(self) -> Circuit {
        self.circ
    }

    fn get_next_input_id(&mut self) -> Id {
        let id = self.next_input_id;
        self.next_input_id += 1;
        id
    }

    fn get_next_ciphertext_id(&mut self) -> Id {
        let id = self.next_ciphertext_id;
        self.next_ciphertext_id += 1;
        id
    }

    fn get_next_ref(&mut self) -> Ref {
        let x = self.next_ref;
        self.next_ref += 1;
        x
    }

    fn gate(&mut self, gate: Gate, modulus: u8) -> Ref {
        self.circ.gates.push(gate);
        self.circ.moduli.push(modulus);
        self.get_next_ref()
    }

    pub fn input(&mut self, modulus: u8) -> Ref {
        let gate = Gate::Input { id: self.get_next_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.input_refs.push(r);
        r
    }

    pub fn inputs(&mut self, n: usize, modulus: u8) -> Vec<Ref> {
        (0..n).map(|_| self.input(modulus)).collect()
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
        assert!(xref < self.next_ref);
        assert!(yref < self.next_ref);
        let xmod = self.circ.moduli[xref];
        let ymod = self.circ.moduli[yref];
        assert!(xmod == ymod);
        let gate = Gate::Add { xref: xref, yref: yref };
        self.gate(gate, xmod)
    }

    pub fn sub(&mut self, xref: Ref, yref: Ref) -> Ref {
        assert!(xref < self.next_ref);
        assert!(yref < self.next_ref);
        let xmod = self.circ.moduli[xref];
        let ymod = self.circ.moduli[yref];
        assert!(xmod == ymod);
        let gate = Gate::Sub { xref: xref, yref: yref };
        self.gate(gate, xmod)
    }

    pub fn cmul(&mut self, xref: Ref, c: u8) -> Ref {
        let modulus = self.circ.moduli[xref];
        self.gate(Gate::Cmul { xref: xref, c: c }, modulus)
    }

    pub fn add_many(&mut self, args: &[Ref]) -> Ref {
        assert!(args.len() > 1);
        let mut z = args[0];
        for &x in args.iter().skip(1) {
            z = self.add(z, x);
        }
        z
    }

    pub fn proj(&mut self, xref: Ref, output_modulus: u8, tt: Vec<u8>) -> Ref {
        assert_eq!(tt.len(), self.circ.moduli[xref] as usize);
        assert!(tt.iter().all(|&x| x < output_modulus));
        let q = output_modulus;
        let gate = Gate::Proj {
            xref: xref,
            tt: tt,
            id: self.get_next_ciphertext_id(),
        };
        self.gate(gate, q)
    }

    // the classic yao binary gate, over mixed moduli!
    pub fn yao(&mut self, xref: Ref, yref: Ref, output_modulus: u8, tt: Vec<Vec<u8>>) -> Ref {
        assert!(tt.iter().all(|ref inner| { inner.iter().all(|&x| x < output_modulus) }));
        let gate = Gate::Yao {
            xref: xref,
            yref: yref,
            tt: tt.clone(),
            id: self.get_next_ciphertext_id()
        };
        self.gate(gate, output_modulus)
    }

    pub fn half_gate(&mut self, xref: Ref, yref: Ref) -> Ref {
        assert_eq!(self.circ.moduli[xref], self.circ.moduli[yref]);
        let gate = Gate::HalfGate {
            xref: xref,
            yref: yref,
            id: self.get_next_ciphertext_id(),
        };
        let q = self.circ.moduli[xref];
        self.gate(gate, q)
    }

    /////////////////////////////////////
    // higher level circuit constructions

    pub fn xor(&mut self, x: Ref, y: Ref) -> Ref {
        assert!(self.circ.moduli[x] == 2);
        assert!(self.circ.moduli[y] == 2);
        self.add(x,y)
    }

    pub fn and(&mut self, x: Ref, y: Ref) -> Ref {
        assert!(self.circ.moduli[x] == 2);
        assert!(self.circ.moduli[y] == 2);
        self.half_gate(x,y)
    }

    pub fn ands(&mut self, args: &[Ref]) -> Ref {
        assert!(args.iter().all(|&x| self.circ.moduli[x] == 2));
        // convert all the wires to base b+1
        let b = args.len();
        let wires: Vec<Ref> = args.iter().map(|&x| {
            self.proj(x, b as u8 + 1, vec![0,1])
        }).collect();
        self._ands(&wires)
    }

    // assumes wires already are in base b+1
    pub fn _ands(&mut self, args: &[Ref]) -> Ref {
        let b = args.len();
        assert!(args.iter().all(|&x| self.circ.moduli[x] == (b + 1) as u8));
        // add them together
        let z = self.add_many(&args);
        // decode the result in base 2
        let mut tab = vec![0;b+1];
        tab[b] = 1;
        self.proj(z, 2, tab)
    }

    pub fn or(&mut self, args: &[Ref]) -> Ref {
        assert!(args.iter().all(|&x| self.circ.moduli[x] == 2));
        // convert all the wires to base b+1
        let b = args.len();
        let wires: Vec<Ref> = args.iter().map(|&x| {
            self.proj(x, b as u8 + 1, vec![0,1])
        }).collect();

        // add them together
        let z = self.add_many(&wires);

        // decode the result in base 2
        let mut tab = vec![1;b+1];
        tab[0] = 0;
        self.proj(z, 2, tab)
    }

    pub fn mul_dlog(&mut self, args: &[Ref]) -> Ref {
        assert!(args.len() > 1);

        // ensure the aguments are compatible
        let q = self.circ.moduli[args[0]];
        if q == 2 {
            // we can't use the dlog trick on mod 2 since we must add in mod p-1
            return self.ands(args)
        }

        assert!(args.iter().all(|&x| self.circ.moduli[x] == q));

        // check if any argument is zero
        let mut eq_zero_tab = vec![0; q as usize];
        eq_zero_tab[0] = 1;
        let bs: Vec<Ref> = args.iter().map(|&x| {
            self.proj(x, 2, eq_zero_tab.clone())
        }).collect();
        let b = self.or(&bs);

        // multiply using the discrete log trick- first project each argument to
        // [dlog_g(x)]_{p-1}
        let tab = dlog_truth_table(q);
        let zs: Vec<Ref> = args.iter().map(|&x| {
            self.proj(x, q-1, tab.clone())
        }).collect();
        let z = self.add_many(&zs);

        // make the truth table for f(b,z) - we flip the arguments for
        // convenience with exp_truth_table.
        let mut f_tt = Vec::with_capacity(2);
        f_tt.push(exp_truth_table(q));
        f_tt.push(vec![0; q as usize]);

        self.yao(b, z, q, f_tt)
    }

    pub fn change_modulus(&mut self, xref: Ref, to_modulus: u8) -> Ref {
        let from_modulus = self.circ.moduli[xref];
        if from_modulus == to_modulus {
            return xref;
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect();
        self.proj(xref, to_modulus, tab)
    }

    ////////////////////////////////////////////////////////////////////////////////
    // binary stuff

    pub fn binary_addition(&mut self, xs: &[Ref], ys: &[Ref]) -> (Vec<Ref>, Ref) {
        assert_eq!(xs.len(), ys.len());
        let (mut z, mut c) = self.half_adder(xs[0], ys[0]);
        let mut bs = vec![z];
        for (&x, &y) in xs.iter().skip(1).zip(ys.iter().skip(1)) {
            let res = self.full_adder(x, y, c);
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        (bs, c)
    }

    fn half_adder(&mut self, x: Ref, y: Ref) -> (Ref, Ref) {
        let z = self.xor(x,y);
        let c = self.and(x,y);
        (z, c)
    }

    fn full_adder(&mut self, x: Ref, y: Ref, c: Ref) -> (Ref, Ref) {
        let z1 = self.xor(x,y);
        let z2 = self.xor(z1,c);
        let c1 = self.and(z1,c);
        let c2 = self.and(x,y);
        let c3 = self.or(&[c1,c2]);
        (z2, c3)
    }

    pub fn twos_complement(&mut self, xs: &[Ref]) -> Vec<Ref> {
        let zs: Vec<Ref> = xs.iter().map(|&x| {
            self.proj(x, 2, vec![1,0])
        }).collect();
        self.add_by_const_1(&zs)
    }

    // helper for twos_complement
    fn add_by_const_1(&mut self, xs: &[Ref]) -> Vec<Ref> {
        let mut c = self.proj(xs[0], 2, vec![0,1]);
        let z = self.negate(xs[0]);
        let mut zs = vec![z];
        for &x in xs.iter().skip(1) {
            let res = self.half_adder(x, c);
            zs.push(res.0);
            c = res.1;
        }
        zs
    }

    pub fn negate(&mut self, x: Ref) -> Ref {
        self.proj(x, 2, vec![1,0])
    }

    // pub fn binary_subtraction_twos_complement(&mut self, xs: &[Ref], ys: &[Ref]) -> (Vec<Ref>, Ref) {
    pub fn binary_subtraction(&mut self, xs: &[Ref], ys: &[Ref]) -> (Vec<Ref>, Ref) {
        let neg_ys = self.twos_complement(&ys);
        let (zs, c) = self.binary_addition(&xs, &neg_ys);
        (zs, self.negate(c))
    }
}


#[cfg(test)]
mod tests {
    use circuit::Builder;
    use rand::Rng;
    use numbers::{u128_to_bits, u128_from_bits};

    #[test]
    fn make_a_circuit() {
        let mut b = Builder::new();
        let x = b.input(3);
        let y = b.input(3);
        let z = b.add(x,y);
        let z = b.cmul(z, 2);
        let z = b.proj(z, 3, vec![1,2,0]); // cyclic shift
        b.output(z);
        let c = b.finish();
        assert_eq!(c.eval(&vec![1,1])[0], 2);
    }

    #[test]
    fn and_gate_fan_n() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + (rng.gen_byte() % 200);
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.ands(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u8> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u8);
            }
            let res = inps.iter().fold(1, |acc, &x| x & acc);
            assert_eq!(c.eval(&inps)[0], res);
        }
    }

    #[test]
    fn or_gate_fan_n() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + (rng.gen_byte() % 200);
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.or(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u8> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u8);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = c.eval(&inps)[0];
            if !(out == res) {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }

    #[test]
    fn mul_dlog() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let q = rng.gen_prime();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.mul_dlog(&[x,y]);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_byte() % q;
            let y = rng.gen_byte() % q;
            assert_eq!(c.eval(&vec![x,y])[0], (x as u16 * y as u16 % q as u16) as u8);
        }
    }

    #[test]
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
            let x = rng.gen_byte() % q;
            let y = rng.gen_byte() % q;
            assert_eq!(c.eval(&vec![x,y])[0], (x as u16 * y as u16 % q as u16) as u8);
        }
    }

    #[test]
    fn change_modulus() {
        let mut rng = Rng::new();
        let mut b = Builder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.input(p);
        let y = b.change_modulus(x, q);
        let z = b.change_modulus(y, p);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_byte() % p;
            assert_eq!(c.eval(&vec![x])[0], x % q);
        }
    }

    #[test]
    fn binary_addition() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let (zs, c) = b.binary_addition(&xs, &ys);
        b.outputs(&zs);
        b.output(c);
        let c = b.finish();
        let mut rng = Rng::new();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = u128_to_bits(x, 128);
            bits.extend(u128_to_bits(y, 128).iter());
            let res = c.eval(&bits);
            let (z, carry) = x.overflowing_add(y);
            assert_eq!(u128_from_bits(&res[0..128]), z);
            assert_eq!(res[128], carry as u8);
        }
    }

    #[test]
    fn binary_subtraction() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let (zs, c) = b.binary_subtraction(&xs, &ys);
        b.outputs(&zs);
        b.output(c);
        let c = b.finish();
        let mut rng = Rng::new();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = u128_to_bits(x, 128);
            bits.extend(u128_to_bits(y, 128).iter());
            let res = c.eval(&bits);
            let (z, carry) = x.overflowing_sub(y);
            assert_eq!(u128_from_bits(&res[0..128]), z);
            assert_eq!(res[128], carry as u8);
        }
    }
}
