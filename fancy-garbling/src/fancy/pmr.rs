//! Module containing `PmrGadgets`, which are the PMR-based gadgets for `Fancy`. These
//! are mostly used internally in CRT gadgets.

use super::{Fancy, HasModulus};
use crate::fancy::bundle::{Bundle, BundleGadgets};
use std::ops::Deref;

/// Bundle which is explicitly PMR-representation.
#[derive(Clone)]
pub struct PmrBundle<W>(Bundle<W>);

impl<W: Clone + HasModulus> Deref for PmrBundle<W> {
    type Target = Bundle<W>;

    fn deref(&self) -> &Bundle<W> {
        &self.0
    }
}

impl<W: Clone + HasModulus> From<Bundle<W>> for PmrBundle<W> {
    fn from(b: Bundle<W>) -> PmrBundle<W> {
        PmrBundle(b)
    }
}

impl<F: Fancy> PmrGadgets for F {}

/// Extension trait for `Fancy` providing advanced PMR gadgets based on bundles of wires.
/// Used internally in CrtGadgets.
pub trait PmrGadgets: Fancy + BundleGadgets {
    // XXX: These functions are from an early version of fancy_garbling. I will port them
    // if it becomes necessary - Brent 3/23/21

    // pub fn pmr_parity(&mut self, xref: BundleRef) -> Ref {
    //     let q = product(&self.bundles[xref.0].primes);
    //     let M = 2*q;

    //     // number of bits to keep in the projection
    //     let nbits = 5;

    //     // used to round
    //     let new_mod = 1_u16 << nbits;

    //     let project = |x: Ref, c: u16, b: &mut Builder| -> Ref {
    //         let p = b.circ.moduli[x];
    //         let Mi = M / p as u128;

    //         // crt coef
    //         let h = inv((Mi % p as u128) as i16, p as i16) as f32;

    //         let mut tab = Vec::with_capacity(p as usize);
    //         for x in 0..p {
    //             let y = ((x+c)%p) as f32 * h / p as f32;
    //             let truncated_y = (new_mod as f32 * y.fract()).round() as u16;
    //             tab.push(truncated_y);
    //         }

    //         b.proj(x, new_mod, tab)
    //     };

    //     let mut C = q/4;
    //     C += C % 2;
    //     let C_crt = crt(&self.bundles[xref.0].primes, C);

    //     let xs: Vec<Ref> = self.bundles[xref.0].wires.to_vec();

    //     let mut b = self.take_builder();
    //     let mut z = None;

    //     for (&x, &c) in xs.iter().zip(C_crt.iter()) {
    //         let y = project(x, c, &mut b);
    //         match z {
    //             None       => z = Some(y),
    //             Some(prev) => z = Some(b.add(prev,y)),
    //         }
    //     }

    //     let tab = (0..new_mod).map(|x| (x >= new_mod/2) as u16).collect();
    //     let out = b.proj(z.unwrap(), 2, tab);
    //     self.put_builder(b);
    //     out
    // }

    // pub fn pmr_bits(&mut self, xref: BundleRef, nbits: usize) -> Vec<Ref> {
    //     let mut bits = Vec::with_capacity(nbits as usize);
    //     let ps = self.bundles[xref.0].primes.clone();
    //     let mut x = xref;
    //     for _ in 0..nbits {
    //         let b = self.parity(x);
    //         bits.push(b);

    //         let wires = ps.iter().map(|&p| self.borrow_mut_builder().mod_change(b,p)).collect();
    //         let bs = self.add_bundle(wires, ps.clone());

    //         x = self.sub(x, bs);
    //         x = self.cdiv(x, 2);
    //     }
    //     bits
    // }

    // pub fn less_than_bits(&mut self, xref: BundleRef, yref: BundleRef, nbits: usize) -> Ref
    // {
    //     let xbits = self.bits(xref, nbits);
    //     let ybits = self.bits(yref, nbits);
    //     self.borrow_mut_builder().binary_subtraction(&xbits, &ybits).1
    // }
}
