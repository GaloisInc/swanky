use itertools::Itertools;

/// A struct is `Fancy` if it implements the basic fancy-garbling functions.
pub trait Fancy {
    type Item: Clone;

    fn constant(&mut self, x: u16, q: u16) -> Self::Item;
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;
    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;
    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;
    fn cmul(&mut self, x: &Self::Item, c: u16) -> Self::Item;
    fn proj(&mut self, x: &Self::Item, q: u16, tt: Vec<u16>) -> Self::Item;
    fn modulus(&self, x: &Self::Item) -> u16;

    ////////////////////////////////////////////////////////////////////////////////
    // bonus functions built on top of basic fancy operations

    /// Sum up a slice of `Self::Item`.
    fn add_many(&mut self, args: &[Self::Item]) -> Self::Item {
        assert!(args.len() > 1);
        let mut z = args[0].clone();
        for x in args.iter().skip(1) {
            z = self.add(&z,&x);
        }
        z
    }

    // TODO: work out free negation
    /// Negate using a projection.
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        assert_eq!(self.modulus(x), 2);
        self.proj(x, 2, vec![1,0])
    }

    /// Xor is just addition, with the requirement that `x` and `y` are mod 2.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        assert!(self.modulus(x) == 2 && self.modulus(y) == 2);
        self.add(x,y)
    }

    /// And is just multiplication, with the requirement that `x` and `y` are mod 2.
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        assert!(self.modulus(x) == 2 && self.modulus(y) == 2);
        self.mul(x,y)
    }

    /// Returns 1 if all `Self::Item` equal 1.
    fn and_many(&mut self, args: &[Self::Item]) -> Self::Item {
        args.iter().skip(1).fold(args[0].clone(), |acc, x| self.and(&acc, x))
    }

    // TODO: with free negation, use demorgans and AND
    /// Returns 1 if any `Self::Item` equals 1 in `args`.
    fn or_many(&mut self, args: &[Self::Item]) -> Self::Item {
        assert!(args.iter().all(|x| self.modulus(x) == 2));
        // convert all the wires to base b+1
        let b = args.len();
        let wires = args.iter().map(|x| {
            self.proj(x, b as u16 + 1, vec![0,1])
        }).collect_vec();

        // add them together
        let z = self.add_many(&wires);

        // decode the result in base 2
        let mut tab = vec![1;b+1];
        tab[0] = 0;
        self.proj(&z,2,tab)
    }

    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(&mut self, x: &Self::Item, to_modulus: u16) -> Self::Item {
        let from_modulus = self.modulus(x);
        if from_modulus == to_modulus {
            return x.clone();
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect();
        self.proj(x, to_modulus, tab)
    }

    ////////////////////////////////////////////////////////////////////////////////
    // mixed radix stuff

    fn mixed_radix_addition(&mut self, xs: &[Vec<Self::Item>]) -> Vec<Self::Item> {
        let nargs = xs.len();
        let n = xs[0].len();
        assert!(xs.iter().all(|x| x.len() == n));

        let mut digit_carry = None;
        let mut carry_carry = None;
        let mut max_carry = 0;

        let mut res = Vec::with_capacity(n);

        for i in 0..n {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x[i].clone()).collect_vec();

            // compute the digit -- easy
            let digit_sum = self.add_many(&ds);
            let digit = digit_carry.map_or(digit_sum.clone(), |d| self.add(&digit_sum, &d));

            if i < n-1 {
                // compute the carries
                let q = self.modulus(&xs[0][i]);
                // max_carry currently contains the max carry from the previous iteration
                let max_val = nargs as u16 * (q-1) + max_carry;
                // now it is the max carry of this iteration
                max_carry = max_val / q;

                let modded_ds = ds.iter().map(|d| self.mod_change(d, max_val+1)).collect_vec();

                let carry_sum = self.add_many(&modded_ds);
                // add in the carry from the previous iteration
                let carry = carry_carry.map_or(carry_sum.clone(), |c| self.add(&carry_sum, &c));

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = self.modulus(&xs[0][i+1]);
                let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
                digit_carry = Some(self.proj(&carry, next_mod, tt));

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n-2 {
                    if max_carry < next_mod {
                        carry_carry = Some(self.mod_change(digit_carry.as_ref().unwrap(), next_max_val + 1));
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).collect_vec();
                        carry_carry = Some(self.proj(&carry, next_max_val + 1, tt));
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


    // fn addition(&mut self, xs: &[Self::Item], ys: &[Self::Item]) -> (Vec<Self::Item>, Self::Item) {
    //     assert_eq!(xs.len(), ys.len());
    //     let cmod = self.modulus(&xs[1]);
    //     let (mut z, mut c) = self.adder(&xs[0], &ys[0], None, cmod);
    //     let mut bs = vec![z];
    //     for i in 1..xs.len() {
    //         let cmod = self.modulus(xs.get(i+1).unwrap_or(&xs[i]));
    //         let res = self.adder(&xs[i], &ys[i], Some(&c), cmod);
    //         z = res.0;
    //         c = res.1;
    //         bs.push(z);
    //     }
    //     (bs, c)
    // }

    // // avoids creating extra gates for the final carry
    // fn addition_no_carry(&mut self, xs: &[Self::Item], ys: &[Self::Item]) -> Vec<Self::Item> {
    //     assert_eq!(xs.len(), ys.len());

    //     let cmod = self.modulus(xs.get(1).unwrap_or(&xs[0]));
    //     let (mut z, mut c) = self.adder(&xs[0], &ys[0], None, cmod);

    //     let mut bs = vec![z];
    //     for i in 1..xs.len()-1 {
    //         let cmod = self.modulus(xs.get(i+1).unwrap_or(&xs[i]));
    //         let res = self.adder(&xs[i], &ys[i], Some(&c), cmod);
    //         z = res.0;
    //         c = res.1;
    //         bs.push(z);
    //     }
    //     z = self.add_many(&[xs.last().unwrap().clone(), ys.last().unwrap().clone(), c]);
    //     bs.push(z);
    //     bs
    // }

    // fn adder(
    //     &mut self,
    //     x: &Self::Item,
    //     y: &Self::Item,
    //     opt_c: Option<&Self::Item>,
    //     carry_modulus: u16) -> (Self::Item, Self::Item)
    // {
    //     let q = self.modulus(x);
    //     assert_eq!(q, self.modulus(y));
    //     if q == 2 {
    //         if let Some(c) = opt_c {
    //             let z1 = self.xor(x,y);
    //             let z2 = self.xor(&z1,c);
    //             let z3 = self.xor(x,c);
    //             let z4 = self.and(&z1,&z3);
    //             let mut carry = self.xor(&z4,x);
    //             if carry_modulus != 2 {
    //                 carry = self.mod_change(&carry, carry_modulus);
    //             }
    //             (z2, carry)
    //         } else {
    //             let z = self.xor(x,y);
    //             let mut carry = self.and(x,y);
    //             if carry_modulus != 2 {
    //                 carry = self.mod_change(&carry, carry_modulus);
    //             }
    //             (z, carry)
    //         }
    //     } else {
    //         let (sum, qp, zp);

    //         if let Some(c) = opt_c {
    //             let z = self.add(x,y);
    //             sum = self.add(&z, c);
    //             qp = 2*q;
    //         } else {
    //             sum = self.add(x,y);
    //             qp = 2*q-1;
    //         }

    //         let xp = self.mod_change(x, qp);
    //         let yp = self.mod_change(y, qp);

    //         if let Some(c) = opt_c {
    //             let cp = self.mod_change(c, qp);
    //             zp = self.add_many(&[xp, yp, cp]);
    //         } else {
    //             zp = self.add(&xp, &yp);
    //         }

    //         let tt = (0..qp).map(|x| u16::from(x >= q)).collect();
    //         let carry = self.proj(&zp, carry_modulus, tt);
    //         (sum, carry)
    //     }
    // }

    // fn twos_complement(&mut self, xs: &[Self::Item]) -> Vec<Self::Item> {
    //     let not_xs = xs.iter().map(|x| self.negate(x)).collect_vec();
    //     let zero = self.constant(0,2);
    //     let mut const1 = vec![zero; xs.len()];
    //     const1[0] = self.constant(1,2);
    //     self.addition_no_carry(&not_xs, &const1)
    // }

    // fn binary_subtraction(
    //     &mut self, xs: &[Self::Item], ys: &[Self::Item]
    // ) -> (Vec<Self::Item>, Self::Item) {
    //     let neg_ys = self.twos_complement(&ys);
    //     let (zs, c) = self.addition(&xs, &neg_ys);
    //     (zs, self.negate(&c))
    // }
}
