//! Homomorphic commitment functionality.
//!
//! It includes `random`, `input`, affine operations,
//! `check_zero`, `open` and `check_multiply`.
//! These functionalities are used for diet Mac'n'Cheese and in the edabits
//! conversion protocol for field-switching.
use eyre::{eyre, Result};
use generic_array::{typenum::Unsigned, GenericArray};
use log::{debug, info, warn};
use ocelot::svole::{LpnParams, Receiver, Sender};
use rand::{Rng, SeedableRng};
use scuttlebutt::field::{Degree, DegreeModulo, IsSubFieldOf};
use scuttlebutt::serialization::CanonicalSerialize;
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};
use std::{marker::PhantomData, time::Instant};
use subtle::{Choice, ConditionallySelectable};

/// This type holds the prover-side data associated with a MAC between a prover
/// and verifier (see [`MacVerifier`] for the verifier-side data).
///
/// The main property associated with the two types is that, given a
/// `MacProver(v, t)` and its corresponding `MacVerifier(k)`, the following
/// equation holds for a global key `Δ` known only to the verifier: `t = v · Δ +
/// k`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MacProver<V: IsSubFieldOf<T>, T: FiniteField>(
    /// The prover's value `v`.
    V,
    /// The prover's MAC tag `t`.
    T,
)
where
    T::PrimeField: IsSubFieldOf<V>;

impl<V: IsSubFieldOf<T>, T: FiniteField> MacProver<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(x: V, m: T) -> Self {
        Self(x, m)
    }

    pub fn value(&self) -> V {
        self.0
    }

    pub fn mac(&self) -> T {
        self.1
    }

    pub fn decompose(&self) -> (V, T) {
        (self.0, self.1)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Default for MacProver<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn default() -> Self {
        Self::new(V::ZERO, T::ZERO)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> ConditionallySelectable for MacProver<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MacProver(
            V::conditional_select(&a.0, &b.0, choice),
            T::conditional_select(&a.1, &b.1, choice),
        )
    }
}

/// This type holds the verifier-side data associated with a MAC between a
/// prover and verifier (see [`MacProver`] for the prover-side data).
///
/// The main property associated with the two types is that, given a
/// `MacProver(v, t)` and its corresponding `MacVerifier(k)`, the following
/// equation holds for a global key `Δ` known only to the verifier: `t = v · Δ +
/// k`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MacVerifier<F: FiniteField>(
    /// The verifier's MAC key `k`.
    F,
);

impl<F: FiniteField> MacVerifier<F> {
    pub fn new(k: F) -> Self {
        Self(k)
    }

    pub fn mac(&self) -> F {
        self.0
    }
}

impl<F: FiniteField> Default for MacVerifier<F> {
    fn default() -> Self {
        Self::new(F::ZERO)
    }
}

impl<FE: FiniteField> ConditionallySelectable for MacVerifier<FE> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MacVerifier(FE::conditional_select(&a.0, &b.0, choice))
    }
}

#[cfg(test)]
pub(crate) fn validate<V: IsSubFieldOf<T>, T: FiniteField>(
    prover: MacProver<V, T>,
    verifier: MacVerifier<T>,
    delta: T,
) -> bool
where
    T::PrimeField: IsSubFieldOf<V>,
{
    prover.value() * delta + verifier.mac() == prover.mac()
}

/// F_com protocol for the Prover
pub struct FComProver<V: IsSubFieldOf<T>, T: FiniteField> {
    svole_sender: Sender<T>,
    voles: Vec<(V, T)>,
}

fn make_x_i<V: IsSubFieldOf<T>, T: FiniteField>(i: usize) -> T {
    let mut v: GenericArray<V, DegreeModulo<V, T>> = GenericArray::default();
    v[i] = V::ONE;
    T::from_subfield(&v)
}

pub struct StateMultCheckProver<FE> {
    sum_a0: FE,
    sum_a1: FE,
    chi_power: FE,
    chi: FE,
    cnt: usize,
}

impl<FE> Drop for StateMultCheckProver<FE> {
    fn drop(&mut self) {
        if self.cnt != 0 {
            warn!(
                "Quicksilver functionality dropped before check finished, mult cnt {:?}",
                self.cnt
            );
        }
    }
}

impl<FE: FiniteField> StateMultCheckProver<FE> {
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self> {
        channel.flush()?;
        let chi = channel.read_serializable()?;
        Ok(StateMultCheckProver {
            sum_a0: FE::ZERO,
            sum_a1: FE::ZERO,
            chi_power: chi,
            chi,
            cnt: 0,
        })
    }

    pub fn reset(&mut self) {
        self.sum_a0 = FE::ZERO;
        self.sum_a1 = FE::ZERO;
        self.chi_power = self.chi;
        self.cnt = 0;
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> FComProver<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize the functionality.
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        Ok(Self {
            svole_sender: Sender::init(channel, rng, lpn_setup, lpn_extend)?,
            voles: Vec::new(),
        })
    }

    /// Duplicate the functionality.
    pub fn duplicate<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<Self> {
        Ok(Self {
            svole_sender: self.svole_sender.duplicate(channel, rng)?,
            voles: Vec::new(),
        })
    }

    /// Returns a random mac.
    pub fn random<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<MacProver<V, T>> {
        match self.voles.pop() {
            Some(e) => Ok(MacProver(e.0, e.1)),
            None => {
                self.svole_sender.send(channel, rng, &mut self.voles)?;
                match self.voles.pop() {
                    Some(e) => Ok(MacProver(e.0, e.1)),
                    None => Err(eyre!("svole failed for random")),
                }
            }
        }
    }

    /// Input a slice of values and returns a vector of its macs.
    pub fn input<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x: &[V],
    ) -> Result<Vec<T>> {
        let mut out = Vec::with_capacity(x.len());
        self.input_low_level(channel, rng, x, &mut out)?;
        Ok(out)
    }

    /// lower level implementation of `input` with pre-defined out vector.
    pub fn input_low_level<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x: &[V],
        out: &mut Vec<T>,
    ) -> Result<()> {
        for x_i in x {
            let r = self.random(channel, rng)?;
            let y = *x_i - r.0;
            out.push(r.1);
            channel.write_serializable::<V>(&y)?;
        }
        Ok(())
    }

    /// Input a single value and returns its mac.
    pub fn input1<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x: V,
    ) -> Result<T> {
        let r = self.random(channel, rng)?;
        let y = x - r.0;
        channel.write_serializable::<V>(&y)?;
        Ok(r.1)
    }

    /// Add a constant to a Mac.
    #[inline]
    pub fn affine_add_cst(&self, cst: V, x: MacProver<V, T>) -> MacProver<V, T> {
        MacProver(cst + x.0, x.1)
    }

    /// Multiply by a constant a Mac.
    #[inline]
    pub fn affine_mult_cst(&self, cst: V, x: MacProver<V, T>) -> MacProver<V, T> {
        MacProver(cst * x.0, cst * (x.1))
    }

    /// Add two Macs.
    #[inline]
    pub fn add(&self, a: MacProver<V, T>, b: MacProver<V, T>) -> MacProver<V, T> {
        let MacProver(a, a_mac) = a;
        let MacProver(b, b_mac) = b;
        MacProver(a + b, a_mac + b_mac)
    }

    /// Negative Mac.
    #[inline]
    pub fn neg(&self, a: MacProver<V, T>) -> MacProver<V, T> {
        let MacProver(a, a_mac) = a;
        MacProver(-a, -a_mac)
    }

    /// Subtraction of two Macs.
    #[inline]
    pub fn sub(&self, a: MacProver<V, T>, b: MacProver<V, T>) -> MacProver<V, T> {
        let MacProver(a, a_mac) = a;
        let MacProver(b, b_mac) = b;
        MacProver(a - b, a_mac - b_mac)
    }

    /// Check that a batch of Macs are zero.
    pub fn check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x_mac_batch: &[MacProver<V, T>],
    ) -> Result<()> {
        let seed = channel.read_block()?;
        let mut rng = AesRng::from_seed(seed);

        let mut m = T::ZERO;
        let mut b = true;
        for MacProver(x, x_mac) in x_mac_batch.iter() {
            b = b && *x == V::ZERO;
            let chi = T::random(&mut rng);
            m += chi * *x_mac;
        }
        channel.write_serializable::<T>(&m)?;
        channel.flush()?;

        if b {
            Ok(())
        } else {
            warn!("check_zero fails");
            Err(eyre!("check_zero failed"))
        }
    }

    /// Open Macs.
    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        batch: &[MacProver<V, T>],
    ) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        for MacProver(x, _) in batch.iter() {
            channel.write_serializable::<V>(x)?;
            hasher.update(&x.to_bytes());
        }

        let seed = Block::try_from_slice(&hasher.finalize().as_bytes()[0..16]).unwrap();
        let mut rng = AesRng::from_seed(seed);

        let mut m = T::ZERO;
        for MacProver(_, x_mac) in batch.iter() {
            let chi = T::random(&mut rng);
            m += chi * *x_mac;
        }
        channel.write_serializable::<T>(&m)?;
        channel.flush()?;

        Ok(())
    }

    /// Quicksilver multiplication check.
    pub fn quicksilver_check_multiply<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        triples: &[(MacProver<V, T>, MacProver<V, T>, MacProver<V, T>)],
    ) -> Result<()> {
        let mut sum_a0 = T::ZERO;
        let mut sum_a1 = T::ZERO;

        let chi = channel.read_serializable()?;
        let mut chi_power = chi;

        for (MacProver(x, x_mac), MacProver(y, y_mac), MacProver(_z, z_mac)) in triples.iter() {
            let a0 = *x_mac * *y_mac;
            let a1 = *y * *x_mac + *x * *y_mac - *z_mac;

            sum_a0 += a0 * chi_power;
            sum_a1 += a1 * chi_power;

            chi_power *= chi;
        }

        // The following block implements VOPE(1)
        let mut mask = T::ZERO;
        let mut mask_mac = T::ZERO;

        for i in 0..Degree::<T>::USIZE {
            let MacProver(u, u_mac) = self.random(channel, rng)?;
            let x_i: T = make_x_i::<V, T>(i);
            mask += u * x_i;
            mask_mac += u_mac * x_i;
        }

        let u = sum_a0 + mask_mac;
        let v = sum_a1 + mask;

        channel.write_serializable(&u)?;
        channel.write_serializable(&v)?;
        channel.flush()?;

        Ok(())
    }

    /// Push a multiplication triplet for later checking.
    pub fn quicksilver_push(
        &mut self,
        state: &mut StateMultCheckProver<T>,
        triple: &(MacProver<V, T>, MacProver<V, T>, MacProver<V, T>),
    ) -> Result<()> {
        let (MacProver(x, x_mac), MacProver(y, y_mac), MacProver(_z, z_mac)) = triple;
        let a0 = *x_mac * *y_mac;
        let a1 = *y * *x_mac + *x * *y_mac - *z_mac;

        state.sum_a0 += a0 * state.chi_power;
        state.sum_a1 += a1 * state.chi_power;
        state.chi_power *= state.chi;
        state.cnt += 1;

        Ok(())
    }

    /// Finalize the check for the list of pushed multiplication triples.
    pub fn quicksilver_finalize<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        state: &mut StateMultCheckProver<T>,
    ) -> Result<usize> {
        // The following block implements VOPE(1)
        let mut mask = T::ZERO;
        let mut mask_mac = T::ZERO;

        for i in 0..Degree::<T>::USIZE {
            let MacProver(u, u_mac) = self.random(channel, rng)?;
            let x_i: T = make_x_i::<V, T>(i);
            mask += u * x_i;
            mask_mac += u_mac * x_i;
        }

        let u = state.sum_a0 + mask_mac;
        let v = state.sum_a1 + mask;

        channel.write_serializable(&u)?;
        channel.write_serializable(&v)?;
        channel.flush()?;
        let c = state.cnt;
        debug!("ERASE ME: quick.cnt {:?}", c);
        state.reset();
        Ok(c)
    }

    /// Reset internal state of functionality
    pub fn reset(&mut self, quick_state: &mut StateMultCheckProver<T>) {
        quick_state.reset();
    }
}

/// F_com protocol for the Verififier
pub struct FComVerifier<V: IsSubFieldOf<T>, T: FiniteField>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    delta: T,
    svole_receiver: Receiver<T>,
    voles: Vec<T>,
    phantom: PhantomData<V>,
}

pub struct StateMultCheckVerifier<FE> {
    sum_b: FE,
    power_chi: FE,
    chi: FE,
    cnt: usize,
}

impl<FE> Drop for StateMultCheckVerifier<FE> {
    fn drop(&mut self) {
        if self.cnt != 0 {
            warn!(
                "Quicksilver functionality dropped before check finished, mult cnt {:?}",
                self.cnt
            );
        }
    }
}

impl<FE: FiniteField> StateMultCheckVerifier<FE> {
    pub fn init<C: AbstractChannel>(channel: &mut C, rng: &mut AesRng) -> Result<Self> {
        let chi = FE::random(rng);
        channel.write_serializable::<FE>(&chi)?;
        channel.flush()?;

        Ok(StateMultCheckVerifier {
            sum_b: FE::ZERO,
            power_chi: chi,
            chi,
            cnt: 0,
        })
    }

    pub fn reset(&mut self) {
        self.sum_b = FE::ZERO;
        self.power_chi = self.chi;
        self.cnt = 0;
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> FComVerifier<V, T>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize the functionality.
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        let recv = Receiver::init(channel, rng, lpn_setup, lpn_extend)?;
        Ok(Self {
            delta: recv.delta(),
            svole_receiver: recv,
            voles: Vec::new(),
            phantom: PhantomData,
        })
    }

    /// Duplicate the functionality.
    pub fn duplicate<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<Self> {
        Ok(Self {
            delta: self.get_delta(),
            svole_receiver: self.svole_receiver.duplicate::<_, V>(channel, rng)?,
            voles: Vec::new(),
            phantom: PhantomData,
        })
    }

    /// Returns the delta Mac.
    #[inline]
    pub fn get_delta(&self) -> T {
        self.delta
    }

    /// Returns a random mac.
    pub fn random<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<MacVerifier<T>> {
        match self.voles.pop() {
            Some(e) => Ok(MacVerifier(e)),
            None => {
                let _start = Instant::now();
                self.svole_receiver.receive(channel, rng, &mut self.voles)?;
                info!(
                    "SVOLE<time:{:?} field:{:?}>",
                    _start.elapsed(),
                    (T::ZERO - T::ONE).to_bytes()
                );
                match self.voles.pop() {
                    Some(e) => Ok(MacVerifier(e)),
                    None => Err(eyre!("svole failed for random")),
                }
            }
        }
    }

    /// Input a number of values and returns the associated macs.
    pub fn input<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
    ) -> Result<Vec<MacVerifier<T>>> {
        let mut out = Vec::with_capacity(num);
        self.input_low_level(channel, rng, num, &mut out)?;
        Ok(out)
    }

    /// lower level implementation of `input` for predefined  out vector.
    pub fn input_low_level<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
        out: &mut Vec<MacVerifier<T>>,
    ) -> Result<()> {
        for _i in 0..num {
            let r = self.random(channel, rng)?;
            let y = channel.read_serializable::<T::PrimeField>()?;
            out.push(MacVerifier(r.0 - y * self.delta));
        }
        Ok(())
    }

    /// Input a single value and returns its associated Mac.
    pub fn input1<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<MacVerifier<T>> {
        let r = self.random(channel, rng)?;
        let y = channel.read_serializable::<T::PrimeField>()?;
        let out = MacVerifier(r.0 - y * self.delta);
        Ok(out)
    }

    /// Add a constant to a Mac.
    #[inline]
    pub fn affine_add_cst(&self, cst: T::PrimeField, x_mac: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier(x_mac.0 - cst * self.delta)
    }

    /// Multiply a Mac by a constant.
    #[inline]
    pub fn affine_mult_cst(&self, cst: T::PrimeField, x_mac: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier(cst * x_mac.0)
    }

    /// Add two Macs.
    #[inline]
    pub fn add(&self, a: MacVerifier<T>, b: MacVerifier<T>) -> MacVerifier<T> {
        let MacVerifier(a_mac) = a;
        let MacVerifier(b_mac) = b;
        MacVerifier(a_mac + b_mac)
    }

    /// Negative of a Mac.
    #[inline]
    pub fn neg(&self, a: MacVerifier<T>) -> MacVerifier<T> {
        let MacVerifier(a_mac) = a;
        MacVerifier(-a_mac)
    }

    /// Subtraction of two Macs.
    #[inline]
    pub fn sub(&self, a: MacVerifier<T>, b: MacVerifier<T>) -> MacVerifier<T> {
        let MacVerifier(a_mac) = a;
        let MacVerifier(b_mac) = b;
        MacVerifier(a_mac - b_mac)
    }

    /// Check that a batch of Macs are zero.
    pub fn check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        key_batch: &[MacVerifier<T>],
    ) -> Result<()> {
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let mut rng = AesRng::from_seed(seed);

        let mut key_chi = T::ZERO;
        for MacVerifier(key) in key_batch.iter() {
            let chi = T::random(&mut rng);
            key_chi += chi * *key;
        }
        let m = channel.read_serializable::<T>()?;

        let b = key_chi == m;

        if b {
            Ok(())
        } else {
            Err(eyre!("check_zero failed"))
        }
    }

    /// Open Macs.
    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        keys: &[MacVerifier<T>],
        out: &mut Vec<T::PrimeField>,
    ) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        out.clear();
        for _ in 0..keys.len() {
            let x = channel.read_serializable::<T::PrimeField>()?;
            out.push(x);
            hasher.update(&x.to_bytes());
        }
        let seed = Block::try_from_slice(&hasher.finalize().as_bytes()[0..16]).unwrap();
        let mut rng = AesRng::from_seed(seed);

        let mut key_chi = T::ZERO;
        let mut x_chi = T::ZERO;
        for i in 0..keys.len() {
            let chi = T::random(&mut rng);
            let MacVerifier(key) = keys[i];
            let x = out[i];

            key_chi += chi * key;
            x_chi += x * chi;
        }
        let m = channel.read_serializable::<T>()?;

        assert_eq!(out.len(), keys.len());
        if key_chi + self.delta * x_chi == m {
            Ok(())
        } else {
            warn!("check_zero fails");
            Err(eyre!("open fails"))
        }
    }

    /// Quicksilver multiplication check.
    pub fn quicksilver_check_multiply<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        triples: &[(MacVerifier<T>, MacVerifier<T>, MacVerifier<T>)],
    ) -> Result<()> {
        let chi = T::random(rng);
        channel.write_serializable::<T>(&chi)?;
        channel.flush()?;

        let mut sum_b = T::ZERO;
        let mut power_chi = chi;

        for (MacVerifier(x_mac), MacVerifier(y_mac), MacVerifier(z_mac)) in triples.iter() {
            //  should be `- (-delta)` with our conventions compared to
            //  quicksilver but simplified out.
            let b = (*x_mac) * (*y_mac) + self.delta * *z_mac;

            sum_b += b * power_chi;
            power_chi *= chi;
        }

        // The following block implements VOPE(1)
        let mut mask_mac = T::ZERO;
        for i in 0..Degree::<T>::USIZE {
            let MacVerifier(v_m) = self.random(channel, rng)?;
            let x_i: T = make_x_i::<T::PrimeField, T>(i);
            mask_mac += v_m * x_i;
        }

        let u = channel.read_serializable::<T>()?;
        let v = channel.read_serializable::<T>()?;

        let b_plus = sum_b + mask_mac;
        if b_plus == (u + (-self.delta) * v) {
            // - because of delta
            Ok(())
        } else {
            Err(eyre!("checkMultiply fails"))
        }
    }

    /// Push multiplication triple for later check.
    pub fn quicksilver_push(
        &mut self,
        state: &mut StateMultCheckVerifier<T>,
        triple: &(MacVerifier<T>, MacVerifier<T>, MacVerifier<T>),
    ) -> Result<()> {
        let (MacVerifier(x_mac), MacVerifier(y_mac), MacVerifier(z_mac)) = triple;
        //  should be `- (-delta)` with our conventions compared to
        //  quicksilver but simplified out.
        let b = (*x_mac) * (*y_mac) + self.delta * *z_mac;

        state.sum_b += b * state.power_chi;
        state.power_chi *= state.chi;
        state.cnt += 1;
        Ok(())
    }

    /// Finalize the check for the list of pushed multiplication triples.
    pub fn quicksilver_finalize<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        state: &mut StateMultCheckVerifier<T>,
    ) -> Result<usize> {
        // The following block implements VOPE(1)
        let mut mask_mac = T::ZERO;
        for i in 0..Degree::<T>::USIZE {
            let MacVerifier(v_m) = self.random(channel, rng)?;
            let x_i: T = make_x_i::<T::PrimeField, T>(i);
            mask_mac += v_m * x_i;
        }

        let u = channel.read_serializable::<T>()?;
        let v = channel.read_serializable::<T>()?;

        let b_plus = state.sum_b + mask_mac;
        if b_plus == (u + (-self.delta) * v) {
            // - because of delta
            let c = state.cnt;
            debug!("ERASE ME: quick.cnt {:?}", c);
            state.reset();
            Ok(c)
        } else {
            state.reset();
            Err(eyre!("checkMultiply fails"))
        }
    }

    /// Reset internal state of functionality
    pub fn reset(&mut self, quick_state: &mut StateMultCheckVerifier<T>) {
        quick_state.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::{FComProver, FComVerifier, MacProver};
    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::SeedableRng;
    use scuttlebutt::{
        field::{F40b, F61p, FiniteField},
        ring::FiniteRing,
        AbstractChannel, AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_fcom_random<FE: FiniteField>() {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<FE::PrimeField, FE>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(fcom.random(&mut channel, &mut rng).unwrap());
            }
            fcom.open(&mut channel, &v).unwrap();
            v
        });
        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComVerifier::<FE::PrimeField, FE>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(fcom.random(&mut channel, &mut rng).unwrap());
        }

        let mut r = Vec::new();
        fcom.open(&mut channel, &v, &mut r).unwrap();

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], resprover[i].0);
        }
    }

    fn test_fcom_affine() {
        let count = 200;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<F61p, F61p>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let MacProver(x, x_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let cst = F61p::random(&mut rng);
                channel.write_serializable::<F61p>(&cst).unwrap();
                channel.flush().unwrap();
                let m = fcom.affine_mult_cst(cst, MacProver(x, x_mac));
                v.push(m);
                let a = fcom.affine_add_cst(cst, MacProver(x, x_mac));
                v.push(a);
            }
            fcom.open(&mut channel, &v).unwrap();
            v
        });
        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComVerifier::<F61p, F61p>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let x_mac = fcom.random(&mut channel, &mut rng).unwrap();
            let cst = channel.read_serializable().unwrap();
            let m_mac = fcom.affine_mult_cst(cst, x_mac);
            v.push(m_mac);
            let a_mac = fcom.affine_add_cst(cst, x_mac);
            v.push(a_mac);
        }

        let mut r = Vec::new();
        fcom.open(&mut channel, &v, &mut r).unwrap();

        let batch_prover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], batch_prover[i].0);
        }
    }

    fn test_fcom_multiplication<FE: FiniteField>() {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<FE::PrimeField, FE>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let MacProver(x, x_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let MacProver(y, y_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x * y;
                let z_mac = fcom.input(&mut channel, &mut rng, &[z]).unwrap()[0];
                v.push((
                    MacProver(x, x_mac),
                    MacProver(y, y_mac),
                    MacProver(z, z_mac),
                ));
            }
            channel.flush().unwrap();
            fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
                .unwrap();
            v
        });
        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComVerifier::<FE::PrimeField, FE>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let xmac = fcom.random(&mut channel, &mut rng).unwrap();
            let ymac = fcom.random(&mut channel, &mut rng).unwrap();
            let zmac = fcom.input(&mut channel, &mut rng, 1).unwrap()[0];
            v.push((xmac, ymac, zmac));
        }
        fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
            .unwrap();

        handle.join().unwrap();
    }

    fn test_fcom_check_zero<FE: FiniteField>() {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<FE::PrimeField, FE>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            for n in 0..count {
                // ZEROs
                let mut v = Vec::new();
                for _ in 0..n {
                    let x = FE::PrimeField::ZERO;
                    let xmac = fcom.input1(&mut channel, &mut rng, x).unwrap();
                    v.push(MacProver(x, xmac));
                }
                channel.flush().unwrap();
                let r = fcom.check_zero(&mut channel, v.as_slice());
                assert!(r.is_ok());
            }

            for n in 1..count {
                // NON_ZERO
                let mut v = Vec::new();
                for _ in 0..n {
                    let x = FE::PrimeField::random_nonzero(&mut rng);
                    let xmac = fcom.input1(&mut channel, &mut rng, x).unwrap();
                    v.push(MacProver(x, xmac));
                }
                channel.flush().unwrap();
                let r = fcom.check_zero(&mut channel, v.as_slice());
                assert!(r.is_err());
            }
        });
        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComVerifier::<FE::PrimeField, FE>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        for n in 0..count {
            // ZEROs
            let mut v = Vec::new();
            for _ in 0..n {
                let xmac = fcom.input1(&mut channel, &mut rng).unwrap();
                v.push(xmac);
            }
            let r = fcom.check_zero(&mut channel, &mut rng, &v);
            assert!(r.is_ok());
        }

        for n in 1..count {
            // non ZERO
            let mut v = Vec::new();
            for _ in 0..n {
                let xmac = fcom.input1(&mut channel, &mut rng).unwrap();
                v.push(xmac);
            }
            let r = fcom.check_zero(&mut channel, &mut rng, &v);
            assert!(r.is_err());
        }

        handle.join().unwrap();
    }

    #[test]
    fn test_fcom_random_f61p() {
        test_fcom_random::<F61p>();
    }

    #[test]
    fn test_fcom_affine_f61p() {
        test_fcom_affine();
    }

    #[test]
    fn test_fcom_multiplication_check_f61p() {
        test_fcom_multiplication::<F61p>();
    }

    #[test]
    fn test_fcom_multiplication_check_gf40() {
        test_fcom_multiplication::<F40b>();
    }

    #[test]
    fn test_fcom_check_zero_f61p() {
        test_fcom_check_zero::<F61p>();
    }
}
