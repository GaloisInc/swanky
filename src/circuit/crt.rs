use circuit::{Builder, Circuit, Ref};
use numbers::{self, crt, inv, crt_inv, factor, product};
use std::rc::Rc;
use itertools::Itertools;

#[derive(Clone, Copy)]
pub struct BundleRef(usize);

pub struct WireBundle {
    wires: Vec<Ref>,
    primes: Rc<Vec<u16>>,
}

pub struct CrtBundler {
    builder: Option<Builder>,
    bundles: Vec<WireBundle>,
    inputs: Vec<BundleRef>,
    outputs: Vec<BundleRef>,
}

impl CrtBundler {
    pub fn new() -> Self {
        Self::from_builder(Builder::new())
    }

    pub fn primes(&self, x: BundleRef) -> Rc<Vec<u16>> {
        self.bundles[x.0].primes.clone()
    }

    pub fn wires(&self, x: BundleRef) -> Vec<Ref> {
        self.bundles[x.0].wires.to_vec()
    }

    pub fn ninputs(&self) -> usize {
        self.inputs.len()
    }

    fn add_bundle(&mut self, wires: Vec<Ref>, primes: Rc<Vec<u16>>) -> BundleRef {
        assert_eq!(wires.len(), primes.len());
        let bun_ref = self.bundles.len();
        let bun = WireBundle { wires, primes };
        self.bundles.push(bun);
        BundleRef(bun_ref)
    }

    pub fn bundle_from_ref(&mut self, x: Ref, q: u128) -> BundleRef {
        let ps = factor(q);
        let mut ws = Vec::with_capacity(ps.len());
        let input_mod = self.borrow_builder().modulus(x);
        for &output_mod in &ps {
            let tt = (0..input_mod).map(|y| y % output_mod).collect();
            let w = self.borrow_mut_builder().proj(x, output_mod, tt);
            ws.push(w);
        }
        self.add_bundle(ws, Rc::new(ps))
    }

    ////////////////////////////////////////////////////////////////////////////////
    // builder management

    pub fn from_builder(b: Builder) -> Self {
        CrtBundler {
            builder: Some(b),
            bundles: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn take_builder(&mut self) -> Builder {
        self.builder.take().expect("need to own a builder!")
    }

    pub fn put_builder(&mut self, b: Builder) {
        self.builder = Some(b);
    }

    pub fn borrow_mut_builder(&mut self) -> &mut Builder {
        self.builder.as_mut().expect("need to own a builder!")
    }

    pub fn borrow_builder(&self) -> &Builder {
        self.builder.as_ref().expect("need to own a builder!")
    }

    pub fn finish(&mut self) -> Circuit {
        self.take_builder().finish()
    }

    pub fn borrow_circ(&self) -> &Circuit {
        self.borrow_builder().borrow_circ()
    }

    ////////////////////////////////////////////////////////////////////////////////
    // basic methods

    pub fn inputs(&mut self, modulus: u128, n: usize) -> Vec<BundleRef> {
        (0..n).map(|_| self.input(modulus)).collect()
    }

    pub fn input(&mut self, modulus: u128) -> BundleRef {
        let ps = factor(modulus);
        let mut ws = Vec::with_capacity(ps.len());
        for &p in &ps {
            ws.push(self.builder.as_mut().expect("need to own a builder!").input(p));
        }
        let bun_ref = self.add_bundle(ws, Rc::new(ps));
        self.inputs.push(bun_ref);
        bun_ref
    }

    pub fn secret_constant(&mut self, val: u128, modulus: u128) -> BundleRef {
        let ps = factor(modulus);
        let mut ws = Vec::with_capacity(ps.len());
        for &p in &ps {
            let x = (val % p as u128) as u16;
            let w = self.builder.as_mut().expect("need to own a builder!").secret_constant(x, p);
            ws.push(w);
        }
        let bun_ref = self.add_bundle(ws, Rc::new(ps));
        bun_ref
    }

    pub fn constant(&mut self, val: u128, modulus: u128) -> BundleRef {
        let ps = factor(modulus);
        let mut ws = Vec::with_capacity(ps.len());
        for &p in &ps {
            let x = (val % p as u128) as u16;
            let w = self.builder.as_mut().expect("need to own a builder!").constant(x, p);
            ws.push(w);
        }
        let bun_ref = self.add_bundle(ws, Rc::new(ps));
        bun_ref
    }

    pub fn output(&mut self, xref: BundleRef) {
        let b = self.builder.as_mut().expect("need a builder!");
        let ws = &self.bundles[xref.0].wires;
        for &x in ws {
            b.output(x);
        }
        self.outputs.push(xref);
    }

    pub fn output_ref(&mut self, xref: Ref) {
        self.borrow_mut_builder().output(xref);
    }

    pub fn output_refs(&mut self, xs: &[Ref]) {
        self.borrow_mut_builder().outputs(xs);
    }

    pub fn encode(&self, xs: &[u128]) -> Vec<u16> {
        let mut inps = Vec::new();
        for (&x, &xref) in xs.iter().zip(self.inputs.iter()) {
            inps.append(&mut crt(&self.bundles[xref.0].primes, x));
        }
        inps
    }

    pub fn decode(&self, outs: &[u16]) -> Vec<u128> {
        let mut outs = outs.to_vec();
        let mut res = Vec::with_capacity(self.outputs.len());
        for &zref in self.outputs.iter() {
            let z = &self.bundles[zref.0];
            let rest = outs.split_off(z.primes.len());
            res.push(crt_inv(&z.primes, &outs));
            outs = rest;
        }
        res
    }

    ////////////////////////////////////////////////////////////////////////////////
    // general circuit construction functions

    pub fn add(&mut self, xref: BundleRef, yref: BundleRef) -> BundleRef {
        let xwires = self.wires(xref);
        let ywires = self.wires(yref);
        assert_eq!(xwires.len(), ywires.len());
        let zwires = xwires.into_iter().zip(ywires.into_iter()).map(|(x,y)|
            self.borrow_mut_builder().add(x,y)
        ).collect();
        let primes = self.primes(xref);
        self.add_bundle(zwires, primes)
    }

    pub fn sub(&mut self, xref: BundleRef, yref: BundleRef) -> BundleRef {
        let xwires = self.wires(xref);
        let ywires = self.wires(yref);
        assert_eq!(xwires.len(), ywires.len());
        let zwires = xwires.into_iter().zip(ywires.into_iter()).map(|(x,y)|
            self.borrow_mut_builder().sub(x,y)
        ).collect();
        let primes = self.primes(xref);
        self.add_bundle(zwires, primes)
    }

    pub fn cmul(&mut self, xref: BundleRef, c: u128) -> BundleRef {
        let xwires = self.wires(xref);
        let primes = self.primes(xref);

        let cs = crt(&primes, c);

        let zwires = xwires.iter().zip(&cs).map(|(&x, &c)|
            self.borrow_mut_builder().cmul(x,c)
        ).collect();
        self.add_bundle(zwires, primes)
    }

    pub fn secret_cmul(&mut self, xbun: BundleRef, c: u128) -> BundleRef {
        let xwires = self.wires(xbun);
        let primes = self.primes(xbun);
        let cs = crt(&primes, c);
        let mut zwires = Vec::with_capacity(xwires.len());
        for i in 0..xwires.len() {
            let tt = (0..primes[i]).map(|x| (x * cs[i]) % primes[i]).collect();
            let z = self.borrow_mut_builder().proj(xwires[i], primes[i], tt);
            zwires.push(z);
        }
        self.add_bundle(zwires, primes)
    }

    pub fn cdiv(&mut self, xref: BundleRef, c: u16) -> BundleRef {
        let xwires = self.wires(xref);
        let primes = self.primes(xref);
        let zwires = xwires.into_iter().zip(primes.iter()).map(|(x,&p)|
            if c % p == 0 {
                self.borrow_mut_builder().cmul(x,0)
            } else {
                let d = inv(c as i16, p as i16) as u16;
                self.borrow_mut_builder().cmul(x,d)
            }
        ).collect();
        self.add_bundle(zwires, primes)
    }

    pub fn cexp(&mut self, xref: BundleRef, c: u16) -> BundleRef {
        let xwires = self.wires(xref);
        let primes = self.primes(xref);
        let zwires = xwires.into_iter().zip(primes.iter()).map(|(x, &p)| {
            let tab = (0..p).map(|x| {
                ((x as u64).pow(c as u32) % p as u64) as u16
            }).collect();
            self.borrow_mut_builder().proj(x, p, tab)
        }).collect();
        self.add_bundle(zwires, primes)
    }

    pub fn rem(&mut self, xref: BundleRef, p: u16) -> BundleRef {
        let xwires = self.wires(xref);
        let primes = self.primes(xref);
        let i = primes.iter().position(|&q| p == q).expect("p is not one of the primes in this bundle!");
        let x = xwires[i];
        let zwires = primes.iter().map(|&q| self.borrow_mut_builder().mod_change(x, q)).collect();
        self.add_bundle(zwires, primes)
    }

    pub fn mul(&mut self, xref: BundleRef, yref: BundleRef) -> BundleRef {
        let xwires = self.wires(xref);
        let ywires = self.wires(yref);
        let primes = self.primes(xref);
        let zwires = xwires.into_iter().zip(ywires.into_iter()).map(|(x,y)|
            self.borrow_mut_builder().half_gate(x,y)
        ).collect();
        self.add_bundle(zwires, primes)
    }

    pub fn eq(&mut self, xref: BundleRef, yref: BundleRef) -> Ref {
        let xwires = self.wires(xref);
        let ywires = self.wires(yref);
        let primes = self.primes(xref);
        let mut zs = Vec::with_capacity(xwires.len());
        for i in 0..xwires.len() {
            let subbed = self.borrow_mut_builder().sub(xwires[i], ywires[i]);
            let mut eq_zero_tab = vec![0; primes[i] as usize];
            eq_zero_tab[0] = 1;
            let z = self.borrow_mut_builder().proj(subbed, xwires.len() as u16 + 1, eq_zero_tab);
            zs.push(z);
        }
        self.borrow_mut_builder()._and_many(&zs)
    }

    pub fn crt_to_pmr(&mut self, xref: BundleRef) -> BundleRef {
        let gadget_projection_tt = |p, q| -> Vec<u16> {
            let pq = p as u32 + q as u32 - 1;
            let mut tab = Vec::with_capacity(pq as usize);
            for z in 0 .. pq {
                let mut x = 0;
                let mut y = 0;
                'outer: for i in 0..p as u32 {
                    for j in 0..q as u32 {
                        if (i + pq - j) % pq == z {
                            x = i;
                            y = j;
                            break 'outer;
                        }
                    }
                }
                assert_eq!((x + pq - y) % pq, z);
                tab.push((((x * q as u32 * inv(q as i16, p as i16) as u32 +
                            y * p as u32 * inv(p as i16, q as i16) as u32) / p as u32) % q as u32) as u16);
            }
            tab
        };

        let gadget = |b: &mut Builder, x: Ref, y: Ref| -> Ref {
            let p  = b.circ.modulus(x);
            let q  = b.circ.modulus(y);
            let x_ = b.mod_change(x, p+q-1);
            let y_ = b.mod_change(y, p+q-1);
            let z  = b.sub(x_, y_);
            b.proj(z, q, gadget_projection_tt(p,q))
        };

        let n = self.bundles[xref.0].primes.len();
        let mut x = vec![vec![None; n+1]; n+1];

        for j in 0..n {
            x[0][j+1] = Some(self.bundles[xref.0].wires[j]);
        }

        for i in 1..=n {
            for j in i+1..=n {
                let b = self.builder.as_mut().expect("need a builder!");
                let z = gadget(b, x[i-1][i].unwrap(), x[i-1][j].unwrap());
                x[i][j] = Some(z);
            }
        }

        let mut zwires = Vec::with_capacity(n);
        for i in 0..n {
            zwires.push(x[i][i+1].unwrap());
        }
        let ps = self.bundles[xref.0].primes.clone();
        self.add_bundle(zwires, ps)
    }

    pub fn less_than_pmr(&mut self, xref: BundleRef, yref: BundleRef) -> Ref {
        let z = self.sub(xref, yref);
        let pmr = self.crt_to_pmr(z);
        let n = self.bundles[pmr.0].wires.len();
        let w = self.bundles[pmr.0].wires[n-1];
        let q_in = self.bundles[pmr.0].primes[n-1];
        let mut tab = vec![1; q_in as usize];
        tab[0] = 0;
        self.borrow_mut_builder().proj(w, 2, tab)
    }

    pub fn parity(&mut self, xref: BundleRef) -> Ref {
        let q = product(&self.bundles[xref.0].primes);
        let M = 2*q;

        // number of bits to keep in the projection
        let nbits = 5;

        // used to round
        let new_mod = 1_u16 << nbits;

        let project = |x: Ref, c: u16, b: &mut Builder| -> Ref {
            let p = b.circ.modulus(x);
            let Mi = M / p as u128;

            // crt coef
            let h = inv((Mi % p as u128) as i16, p as i16) as f32;

            let mut tab = Vec::with_capacity(p as usize);
            for x in 0..p {
                let y = ((x+c)%p) as f32 * h / p as f32;
                let truncated_y = (new_mod as f32 * y.fract()).round() as u16;
                tab.push(truncated_y);
            }

            b.proj(x, new_mod, tab)
        };

        let mut C = q/4;
        C += C % 2;
        let C_crt = crt(&self.bundles[xref.0].primes, C);

        let xs = self.bundles[xref.0].wires.to_vec();

        let mut b = self.take_builder();
        let mut z = None;

        for (&x, &c) in xs.iter().zip(C_crt.iter()) {
            let y = project(x, c, &mut b);
            match z {
                None       => z = Some(y),
                Some(prev) => z = Some(b.add(prev,y)),
            }
        }

        let tab = (0..new_mod).map(|x| (x >= new_mod/2) as u16).collect();
        let out = b.proj(z.unwrap(), 2, tab);
        self.put_builder(b);
        out
    }

    pub fn bits(&mut self, xref: BundleRef, nbits: usize) -> Vec<Ref> {
        let mut bits = Vec::with_capacity(nbits as usize);
        let ps = self.bundles[xref.0].primes.clone();
        let mut x = xref;
        for _ in 0..nbits {
            let b = self.parity(x);
            bits.push(b);

            let wires = ps.iter().map(|&p| self.borrow_mut_builder().mod_change(b,p)).collect();
            let bs = self.add_bundle(wires, ps.clone());

            x = self.sub(x, bs);
            x = self.cdiv(x, 2);
        }
        bits
    }

    pub fn less_than_bits(&mut self, xref: BundleRef, yref: BundleRef, nbits: usize) -> Ref
    {
        let xbits = self.bits(xref, nbits);
        let ybits = self.bits(yref, nbits);
        self.borrow_mut_builder().binary_subtraction(&xbits, &ybits).1
    }

    fn fractional_mixed_radix(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> Vec<Ref> {
        let ndigits = factors_of_m.len();
        let q = product(&self.primes(xbun));
        let M = numbers::product(factors_of_m);

        let mut ds = Vec::new();

        let xs = self.wires(xbun);
        let ps = self.primes(xbun);
        let mut b = self.take_builder();

        for (xref, &p) in xs.into_iter().zip(ps.iter()) {

            let mut tabs = vec![Vec::with_capacity(p as usize); ndigits];

            for x in 0..p {
                let crt_coef = inv(((q / p as u128) % p as u128) as i64, p as i64);
                let y = (M as f64 * x as f64 * crt_coef as f64 / p as f64).round() as u128 % M;
                let digits = numbers::as_mixed_radix(y, factors_of_m);
                for i in 0..ndigits {
                    tabs[i].push(digits[i]);
                }
            }

            let new_ds = tabs.into_iter().enumerate()
                .map(|(i,tt)| b.proj(xref, factors_of_m[i], tt))
                .collect_vec();

            ds.push(new_ds);
        }
        let res = b.fancy_addition(&ds);
        self.put_builder(b);
        res
    }

    pub fn relu(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> BundleRef {
        let res = self.fractional_mixed_radix(xbun, factors_of_m);

        // project the MSB to 0/1, whether or not it is less than p/2
        let p = *factors_of_m.last().unwrap();
        let mask_tt = (0..p).map(|x| (x < p/2) as u16).collect();
        let mask = self.borrow_mut_builder().proj(*res.last().unwrap(), 2, mask_tt);

        // use the mask to either output x or 0
        let zwires = self.wires(xbun).into_iter().map(|x| {
            self.borrow_mut_builder().half_gate(x,mask)
        }).collect_vec();

        let primes = self.primes(xbun);
        self.add_bundle(zwires, primes)
    }

    pub fn sgn(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> BundleRef {
        let res = self.fractional_mixed_radix(xbun, factors_of_m);
        let p = *factors_of_m.last().unwrap();
        let tt = (0..p).map(|x| (x >= p/2) as u16).collect();
        let sign = self.borrow_mut_builder().proj(*res.last().unwrap(), 2, tt);

        let ps = self.primes(xbun);
        let q = numbers::product(&ps);
        let mut ws = Vec::with_capacity(ps.len());

        for &p in ps.iter() {
            let tt = vec![ 1, ((q-1) % p as u128) as u16 ];
            let w = self.borrow_mut_builder().proj(sign, p, tt);
            ws.push(w);
        }
        self.add_bundle(ws, ps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garble::garble;
    use numbers::{self, inv, factor, modulus_with_width};
    use rand::thread_rng;
    use util::RngExt;

    const NTESTS: usize = 1;

    // test harnesses {{{
    fn test_garbling(b: &CrtBundler, inp: &[u128], should_be: &[u128]) {
        let circ = b.borrow_builder().borrow_circ();
        let (en, de, ev) = garble(&circ, &mut thread_rng());

        println!("number of ciphertexts: {}", ev.size());

        let enc_inp = b.encode(inp);
        let res = circ.eval(&enc_inp);
        assert_eq!(b.decode(&res), should_be);

        let xs = en.encode(&enc_inp);
        let ys = ev.eval(circ, &xs);
        assert_eq!(b.decode(&de.decode(&ys)), should_be);
    }

    fn test_garbling_high_to_low(b: &CrtBundler, inp: &[u128], should_be: &[u16]) {
        let circ = b.borrow_builder().borrow_circ();
        let (en, de, ev) = garble(&circ, &mut thread_rng());

        println!("number of ciphertexts: {}", ev.size());

        let enc_inp = b.encode(inp);
        let pt_outs: Vec<u16> = circ.eval(&enc_inp);
        assert_eq!(pt_outs, should_be, "inp={:?}", inp);

        let xs = en.encode(&enc_inp);
        let ys = ev.eval(&circ, &xs);
        let gb_outs: Vec<u16> = de.decode(&ys);
        assert_eq!(gb_outs, should_be);
    }

    //}}}
    #[test] //input_output_equal {{{
    fn input_output_equal() {
        let mut rng = thread_rng();
        for _ in 0..NTESTS {
            let q = rng.gen_usable_composite_modulus();

            let mut b = CrtBundler::new();
            let inp = b.input(q);
            b.output(inp);

            let x = rng.gen_u128() % q;
            test_garbling(&mut b, &[x], &[x]);
        }
    }

    //}}}
    #[test] // bundle_from_ref {{{
    fn bundle_from_ref() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let p = rng.gen_prime();
            let q = rng.gen_usable_composite_modulus();

            println!("p={} q={}", p, q);

            let mut b = CrtBundler::new();
            let inp = b.borrow_mut_builder().input(p);
            let bun = b.bundle_from_ref(inp, q);
            b.output(bun);

            let x = rng.gen_u16() % p;
            println!("x={}", x);

            let c = b.finish();
            let (en, de, ev) = garble(&c, &mut thread_rng());

            let res = c.eval(&[x]);
            assert_eq!(b.decode(&res), &[x as u128]);
            let xs = en.encode(&[x]);
            let ys = ev.eval(&c, &xs);
            assert_eq!(b.decode(&de.decode(&ys)), &[x as u128]);
        }
    }

    //}}}
    #[test] // addition {{{
    fn addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.add(x,y);
        b.output(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            test_garbling(&mut b, &[x,y], &[(x+y)%q]);
        }
    }
    //}}}
    #[test] // subtraction {{{
    fn subtraction() {
        let mut rng = thread_rng();

        let q = rng.gen_usable_composite_modulus();

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.sub(x,y);
        b.output(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            test_garbling(&mut b, &[x,y], &[(x+q-y)%q]);
        }
    }
    //}}}
    #[test] // scalar_multiplication {{{
    fn scalar_multiplication() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = modulus_with_width(10);
            let y = rng.gen_u128() % q;
            let mut b = CrtBundler::new();
            let x = b.input(q);
            let z = b.cmul(x,y);
            b.output(z);

            for _ in 0..NTESTS {
                let x = rng.gen_u64() as u128 % q;
                let should_be = x * y % q;
                test_garbling(&mut b, &[x], &[should_be]);
            }
        }
    }
    //}}}
    #[test] // secret scalar_multiplication {{{
    fn secret_scalar_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let y = rng.gen_u64() as u128 % q;

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let z = b.secret_cmul(x,y);
        b.output(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u64() as u128 % q;
            let should_be = x * y % q;
            test_garbling(&mut b, &[x], &[should_be]);
        }
    }
    //}}}
    #[test] // scalar_exponentiation {{{
    fn scalar_exponentiation() {
        let mut rng = thread_rng();
        let q = numbers::modulus_with_width(10);
        let y = rng.gen_u16() % 10;

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let z = b.cexp(x,y);
        b.output(z);

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let should_be = x.pow(y as u32) % q;
            test_garbling(&mut b, &[x], &[should_be]);
        }
    }
    // }}}
    #[test] // remainder {{{
    fn remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let z = b.rem(x,p);
        b.output(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u128() % q;
            let should_be = x % p as u128;
            test_garbling(&mut b, &[x], &[should_be]);
        }
    }
    //}}}
    #[test] // half_gate_multiplication {{{
    fn half_gate_multiplication() {
        let mut rng = thread_rng();
        let q = modulus_with_width(32);

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.mul(x,y);
        b.output(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u64() as u128 % q;
            let y = rng.gen_u64() as u128 % q;
            let should_be = x * y % q;
            test_garbling(&mut b, &[x,y], &[should_be]);
        }
    }
    //}}}
    #[test] // equality {{{
    fn equality() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.eq(x,y);
        b.output_ref(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x == y) as u16;
            test_garbling_high_to_low(&mut b, &[x,y], &[should_be]);
        }
    }
    //}}}
    #[test] // parity {{{
    fn parity() {
        let mut rng = thread_rng();
        let q = numbers::modulus_with_width_skip2(32);
        let mut b = CrtBundler::new();
        let x = b.input(q);
        let z = b.parity(x);
        b.output_ref(z);

        for _ in 0..NTESTS {
            let pt = rng.gen_u128() % (q/2);
            let should_be = (pt % 2) as u16;
            test_garbling_high_to_low(&mut b, &[pt], &[should_be]);
        }
    }
    //}}}
    #[test] // cdiv {{{
    fn cdiv() {
        let mut rng = thread_rng();
        let q = numbers::modulus_with_width_skip2(32);
        let mut b = CrtBundler::new();
        let x = b.input(q);
        let z = b.cdiv(x,2);
        b.output(z);

        for _ in 0..128 {
            let mut pt = rng.gen_u128() % (q/2);
            pt += pt % 2;
            let should_be = pt / 2;
            test_garbling(&mut b, &[pt], &[should_be]);
        }
    }
    //}}}
    #[test] // bits {{{
    fn bits() {
        let mut rng = thread_rng();
        let q = numbers::modulus_with_width_skip2(32);
        let mut b = CrtBundler::new();
        let x = b.input(q);
        let zs = b.bits(x, 32);
        b.output_refs(&zs);

        for _ in 0..NTESTS {
            let pt = rng.gen_u128() % (q/2);
            let should_be = numbers::to_bits(pt, 32);
            test_garbling_high_to_low(&mut b, &[pt], &should_be);
        }
    }
    //}}}
    #[test] // less_than_pmr {{{
    fn less_than_pmr() {
        let mut rng = thread_rng();
        let q = modulus_with_width(32);
        let ps = factor(q);
        let n = ps.len();
        let p = q / ps[n-1] as u128;

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.less_than_pmr(x,y);
        b.output_ref(z);

        for _ in 0..NTESTS {
            let x = rng.gen_u128() % p;
            let y = rng.gen_u128() % p;
            let should_be = (x < y) as u16;
            test_garbling_high_to_low(&mut b, &[x,y], &[should_be]);
        }
    }
    //}}}
    #[test] // less_than_bits {{{
    fn less_than_bits() {
        let mut rng = thread_rng();
        let q = numbers::modulus_with_width_skip2(32);
        let mut b = CrtBundler::new();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.less_than_bits(x, y, 32);
        b.output_ref(z);

        for _ in 0..NTESTS {
            let pt_x = rng.gen_u32() as u128;
            let pt_y = rng.gen_u32() as u128;
            let should_be = (pt_x < pt_y) as u16;
            println!("q={}", q);
            println!("{} {}", pt_x, pt_y);
            test_garbling_high_to_low(&mut b, &[pt_x, pt_y], &[should_be]);
        }
    }
    //}}}
    #[test] // sgn {{{
    fn test_sgn() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        println!("q={}", q);

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let ms = [3,4,54];
        let z = b.sgn(x,&ms);
        b.output(z);

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q/2 { 1 } else { q-1 };
            test_garbling(&mut b, &[pt], &[should_be]);
        }
    }
    //}}}
    #[test] // relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        println!("q={}", q);

        let mut b = CrtBundler::new();
        let x = b.input(q);
        let ms = [3,4,54];
        let z = b.relu(x,&ms);
        b.output(z);

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q/2 { pt } else { 0 };
            test_garbling(&mut b, &[pt], &[should_be]);
        }
    }
    //}}}
    #[test] // pmr {{{
    fn pmr() {
        let mut rng = thread_rng();
        for _ in 0..NTESTS {
            let ps = rng.gen_usable_factors();
            let q = ps.iter().fold(1, |acc, &x| x as u128 * acc);

            let mut b = CrtBundler::new();
            let x = b.input(q);
            let z = b.crt_to_pmr(x);
            b.output(z);

            let pt = rng.gen_u128() % q;

            let should_be = to_pmr_pt(pt, &ps);

            test_garbling_high_to_low(&mut b, &[pt], &should_be)
        }
    }
    fn to_pmr_pt(x: u128, ps: &[u16]) -> Vec<u16> {
        let mut ds = vec![0;ps.len()];
        let mut q = 1;
        for i in 0..ps.len() {
            let p = ps[i] as u128;
            ds[i] = ((x / q) % p) as u16;
            q *= p;
        }
        ds
    }

    fn from_pmr_pt(xs: &[u16], ps: &[u16]) -> u128 {
        let mut x = 0;
        let mut q = 1;
        for (&d,&p) in xs.iter().zip(ps.iter()) {
            x += d as u128 * q;
            q *= p as u128;
        }
        x
    }

    fn gadget_projection_tt(p: u16, q: u16) -> Vec<u16> {
        let pq = p as u32 + q as u32 - 1;
        let mut tab = Vec::with_capacity(pq as usize);
        for z in 0 .. pq {
            let mut x = 0;
            let mut y = 0;
            'outer: for i in 0..p as u32 {
                for j in 0..q as u32 {
                    if (i + pq - j) % pq == z {
                        x = i;
                        y = j;
                        break 'outer;
                    }
                }
            }
            assert_eq!((x + pq - y) % pq, z);
            tab.push((((x * q as u32 * inv(q as i16, p as i16) as u32 +
                        y * p as u32 * inv(p as i16, q as i16) as u32) / p as u32) % q as u32) as u16);
        }
        tab
    }

    pub fn to_pmr_alg(inp:u128, ps: &[u16]) -> (Vec<u16>, Vec<u16>) {
        let gadget = |x: u16, p: u16, y: u16, q: u16| {
            let pq = p as u16 + q as u16 - 1;
            let x_ = x as u16 % pq;
            let y_ = y as u16 % pq;
            let z  = (x_ + pq - y_) % pq;
            (gadget_projection_tt(p,q)[z as usize], q)
                // ((z % q as u16) as u16, q)
        };

        let n = ps.len();
        let mut x = vec![vec![None; n+1]; n+1];

        let reduce = |x: u128, p: u16| { (x % p as u128) as u16 };

        for j in 0..n {
            x[0][j+1] = Some( (reduce(inp, ps[j]), ps[j]) );
        }

        for i in 1..n+1 {
            for j in i+1..n+1 {
                let (z,q) = gadget(x[i-1][i].unwrap().0, x[i-1][i].unwrap().1,
                                   x[i-1][j].unwrap().0, x[i-1][j].unwrap().1);
                x[i][j] = Some((z,q));
            }
        }

        let mut zs = Vec::with_capacity(n);
        let mut ps = Vec::with_capacity(n);
        for i in 0..n {
            zs.push(x[i][i+1].unwrap().0);
            ps.push(x[i][i+1].unwrap().1);
        }
        (zs, ps)
    }

    #[test]
    fn pmr_plaintext() {
        let mut rng = thread_rng();
        for _ in 0..NTESTS {
            let ps = rng.gen_usable_factors();
            let q = ps.iter().fold(1, |acc, &x| x as u128 * acc);
            let x = rng.gen_u128() % q;
            assert_eq!(x, from_pmr_pt(&to_pmr_pt(x, &ps), &ps));
            let (pmr, ps_) = to_pmr_alg(x, &ps);

            assert_eq!(ps, ps_);
            assert_eq!(to_pmr_pt(x, &ps), pmr);
        }
    }

    //}}}

}
