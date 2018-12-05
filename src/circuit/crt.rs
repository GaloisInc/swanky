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
        self.add_bundle(ws, Rc::new(ps))
    }

    pub fn constant(&mut self, val: u128, modulus: u128) -> BundleRef {
        let ps = factor(modulus);
        let mut ws = Vec::with_capacity(ps.len());
        for &p in &ps {
            let x = (val % p as u128) as u16;
            let w = self.builder.as_mut().expect("need to own a builder!").constant(x, p);
            ws.push(w);
        }
        self.add_bundle(ws, Rc::new(ps))
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

    ////////////////////////////////////////////////////////////////////////////////
    // fancy methods based on mike's fractional mixed radix trick

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

    // outputs 0/1
    pub fn sign(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> Ref {
        let res = self.fractional_mixed_radix(xbun, factors_of_m);
        let p = *factors_of_m.last().unwrap();
        let tt = (0..p).map(|x| (x >= p/2) as u16).collect();
        self.borrow_mut_builder().proj(*res.last().unwrap(), 2, tt)
    }

    // outputs 1/-1
    pub fn sgn(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> BundleRef {
        let sign = self.sign(xbun, factors_of_m);

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

    fn exact_ms(&self, xbun: BundleRef) -> Vec<u16> {
        match self.primes(xbun).len() {
            3 => vec![2;5],
            4 => vec![3,26],
            5 => vec![3,4,54],
            6 => vec![5,5,6,50],
            7 => vec![6,6,7,7,74],
            8 => vec![5,7,8,8,9,98],
            9 => vec![4,7,10,10,10,10,134],
            n => panic!("unknown exact Ms for {} primes!", n),
        }
    }

    pub fn exact_sgn(&mut self, xbun: BundleRef) -> BundleRef {
        let ms = self.exact_ms(xbun);
        self.sgn(xbun, &ms)
    }

    pub fn exact_relu(&mut self, xbun: BundleRef) -> BundleRef {
        let ms = self.exact_ms(xbun);
        self.relu(xbun, &ms)
    }

    pub fn exact_leq(&mut self, xbun: BundleRef, ybun: BundleRef) -> Ref {
        let ms = self.exact_ms(xbun);
        let zbun = self.sub(xbun, ybun);
        self.sign(zbun, &ms)
    }

    pub fn max(&mut self, buns: &[BundleRef]) -> BundleRef {
        debug_assert!(buns.len() > 1);

        buns.iter().skip(1).fold(buns[0], |xbun, &ybun| {
            let pos = self.exact_leq(xbun,ybun);
            let neg = self.borrow_mut_builder().negate(pos);

            let x_wires = self.wires(xbun);
            let y_wires = self.wires(ybun);

            let z_wires = x_wires.iter().zip(y_wires.iter()).map(|(&x,&y)| {
                let xp = self.borrow_mut_builder().half_gate(x,neg);
                let yp = self.borrow_mut_builder().half_gate(y,pos);
                self.borrow_mut_builder().add(xp,yp)
            }).collect();

            let primes = self.primes(xbun);
            self.add_bundle(z_wires, primes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garble::garble;
    use numbers::{self, modulus_with_width};
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
    #[test] // max {{{
    fn test_max() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let n = 10;
        println!("n={} q={}", n, q);

        let mut b = CrtBundler::new();
        let xs = b.inputs(q, n);
        let z = b.max(&xs);
        b.output(z);

        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % (q/2)).collect_vec();
            println!("{:?}", inps);
            let should_be = *inps.iter().max().unwrap();
            test_garbling(&mut b, &inps, &[should_be]);
        }
    }
    //}}}

}
