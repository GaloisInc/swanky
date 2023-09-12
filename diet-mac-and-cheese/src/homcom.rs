//! Homomorphic commitment functionality.
//!
//! It includes `random`, `input`, affine operations,
//! `check_zero`, `open` and `check_multiply`.
//! These functionalities are used for diet Mac'n'Cheese and in the edabits
//! conversion protocol for field-switching.
use crate::{
    mac::{MacProver, MacVerifier},
    svole_trait::SvoleT,
};
use eyre::{bail, ensure, eyre, Result};
use generic_array::{typenum::Unsigned, GenericArray};
use log::{debug, warn};
use ocelot::svole::LpnParams;
use rand::{Rng, SeedableRng};
use scuttlebutt::field::{DegreeModulo, IsSubFieldOf};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};
use std::marker::PhantomData;

fn make_x_i<V: IsSubFieldOf<T>, T: FiniteField>(i: usize) -> T {
    let mut v: GenericArray<V, DegreeModulo<V, T>> = GenericArray::default();
    v[i] = V::ONE;
    T::from_subfield(&v)
}

/// State to accumulate multiplication checks.
pub struct StateMultCheckProver<T> {
    sum_a0: T,
    sum_a1: T,
    chi_power: T,
    chi: T,
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

impl<T: FiniteField> StateMultCheckProver<T> {
    /// Initialize the state.
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self> {
        channel.flush()?;
        let chi = channel.read_serializable()?;
        Ok(StateMultCheckProver {
            sum_a0: T::ZERO,
            sum_a1: T::ZERO,
            chi_power: chi,
            chi,
            cnt: 0,
        })
    }

    /// Reset the state.
    pub fn reset(&mut self) {
        self.sum_a0 = T::ZERO;
        self.sum_a1 = T::ZERO;
        self.chi_power = self.chi;
        self.cnt = 0;
    }

    /// Return the number of checks accumulated.
    pub fn count(&self) -> usize {
        self.cnt
    }
}

/// State to accumulate check zero.
pub struct StateZeroCheckProver<T> {
    rng: AesRng,
    m: T,
    cnt: usize,
    b: bool,
}

impl<T> Drop for StateZeroCheckProver<T> {
    fn drop(&mut self) {
        if self.cnt != 0 {
            warn!(
                "State for check_zero dropped before check finished, cnt: {:?}",
                self.cnt
            );
        }
    }
}

impl<T: FiniteField> StateZeroCheckProver<T> {
    /// Initialize the state.
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self> {
        let seed = channel.read_block()?;
        let rng = AesRng::from_seed(seed);

        Ok(StateZeroCheckProver {
            rng,
            m: T::ZERO,
            cnt: 0,
            b: true,
        })
    }

    /// Reset the state.
    fn reset(&mut self) {
        // After reset, we assume the internal rng is still synchronized between the prover and the verifier.
        self.m = T::ZERO;
        self.cnt = 0;
        self.b = true;
    }

    /// Return the number of checks accumulated.
    pub fn count(&self) -> usize {
        self.cnt
    }
}

/// Homomorphic commitment scheme from the prover's point-of-view.
pub struct FComProver<V: IsSubFieldOf<T>, T: FiniteField, VOLE: SvoleT<(V, T)>> {
    svole_sender: VOLE,
    voles: Vec<(V, T)>,
}

impl<V: IsSubFieldOf<T>, T: FiniteField, VOLE: SvoleT<(V, T)>> FComProver<V, T, VOLE> {
    /// Initialize the commitment scheme.
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        Ok(Self {
            svole_sender: VOLE::init(channel, rng, lpn_setup, lpn_extend)?,
            voles: Vec::new(),
        })
    }

    pub fn init_with_vole(vole: VOLE) -> Result<Self> {
        Ok(Self {
            svole_sender: vole,
            voles: Vec::new(),
        })
    }

    /// Duplicate the commitment scheme.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            svole_sender: self.svole_sender.duplicate(),
            voles: Vec::new(),
        })
    }

    /// Return a random [`MacProver`].
    pub fn random<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<MacProver<V, T>> {
        match self.voles.pop() {
            Some(e) => Ok(MacProver::new(e.0, e.1)),
            None => {
                self.svole_sender.extend(channel, rng, &mut self.voles)?;
                match self.voles.pop() {
                    Some(e) => Ok(MacProver::new(e.0, e.1)),
                    None => Err(eyre!("svole failed for random")),
                }
            }
        }
    }

    /// Input a slice of commitment values and return a vector of the associated MACs.
    // TODO: should we remove this and just use `input_low_level`?
    pub fn input<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x: &[V],
    ) -> Result<Vec<T>> {
        debug!("input");
        let mut out = Vec::with_capacity(x.len());
        self.input_low_level(channel, rng, x, &mut out)?;
        Ok(out)
    }

    /// Implementation of `input` with a pre-defined output vector.
    pub fn input_low_level<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x: &[V],
        out: &mut Vec<T>,
    ) -> Result<()> {
        debug!("input_low_level");
        for x_i in x {
            let tag = self.input1(channel, rng, *x_i)?;
            out.push(tag);
        }
        Ok(())
    }

    /// Input a single value and returns its MAC.
    pub fn input1<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x: V,
    ) -> Result<T> {
        debug!("input1");
        let r = self.random(channel, rng)?;
        let y = x - r.value();
        channel.write_serializable::<V>(&y)?;
        Ok(r.mac())
    }

    /// Add a constant.
    #[inline]
    pub fn affine_add_cst(&self, cst: V, x: MacProver<V, T>) -> MacProver<V, T> {
        MacProver::new(cst + x.value(), x.mac())
    }

    /// Multiply by a constant.
    #[inline]
    pub fn affine_mult_cst(&self, cst: V, x: MacProver<V, T>) -> MacProver<V, T> {
        MacProver::new(cst * x.value(), cst * x.mac())
    }

    /// Add two [`MacProver`]s.
    #[inline]
    pub fn add(&self, a: MacProver<V, T>, b: MacProver<V, T>) -> MacProver<V, T> {
        let (a, a_mac) = a.decompose();
        let (b, b_mac) = b.decompose();
        MacProver::new(a + b, a_mac + b_mac)
    }

    /// Negate a [`MacProver`].
    #[inline]
    pub fn neg(&self, a: MacProver<V, T>) -> MacProver<V, T> {
        let (a, a_mac) = a.decompose();
        MacProver::new(-a, -a_mac)
    }

    /// Subtract two [`MacProver`]s.
    #[inline]
    pub fn sub(&self, a: MacProver<V, T>, b: MacProver<V, T>) -> MacProver<V, T> {
        let (a, a_mac) = a.decompose();
        let (b, b_mac) = b.decompose();
        MacProver::new(a - b, a_mac - b_mac)
    }

    /// Check that a batch of [`MacProver`]s are zero.
    pub fn check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x_mac_batch: &[MacProver<V, T>],
    ) -> Result<()> {
        debug!("check_zero");
        let seed = channel.read_block()?;
        let mut rng = AesRng::from_seed(seed);

        let mut m = T::ZERO;
        let mut b = true;
        for mac in x_mac_batch.iter() {
            let (x, x_mac) = mac.decompose();
            b = b && x == V::ZERO;
            let chi = T::random(&mut rng);
            m += chi * x_mac;
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

    /// Accumulate a value to zero check into a state.
    pub fn check_zero_accumulate(
        &mut self,
        a: &MacProver<V, T>,
        state: &mut StateZeroCheckProver<T>,
    ) -> Result<()> {
        debug!("check_zero_accumulate");
        let (x, x_mac) = a.decompose();
        let b = x == V::ZERO;
        let chi = T::random(&mut state.rng);
        state.m += chi * x_mac;
        state.cnt += 1;

        if !b {
            warn!("accumulating a value that's not zero");
        }
        state.b = state.b && b;
        Ok(())
    }

    /// Finalize check zero of a state and return how many values were checked.
    pub fn check_zero_finalize<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        state: &mut StateZeroCheckProver<T>,
    ) -> Result<usize> {
        debug!("check_zero_finalize");
        channel.write_serializable::<T>(&state.m)?;
        channel.flush()?;

        if !state.b {
            state.reset();
            return Err(eyre!("check_zero failed"));
        }
        let cnt = state.cnt;
        let b = state.b;
        state.reset();
        ensure!(b, "check zero failed");
        Ok(cnt)
    }

    /// Open a batch of [`MacProver`]s.
    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        batch: &[MacProver<V, T>],
    ) -> Result<()> {
        debug!("open");
        let mut hasher = blake3::Hasher::new();
        for mac in batch.iter() {
            channel.write_serializable::<V>(&mac.value())?;
            hasher.update(&mac.value().to_bytes());
        }

        let seed = Block::try_from_slice(&hasher.finalize().as_bytes()[0..16]).unwrap();
        let mut rng = AesRng::from_seed(seed);

        let mut m = T::ZERO;
        for mac in batch.iter() {
            let chi = T::random(&mut rng);
            m += chi * mac.mac();
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
        debug!("quicksilver_check_multiply");
        let mut sum_a0 = T::ZERO;
        let mut sum_a1 = T::ZERO;

        let chi = channel.read_serializable()?;
        let mut chi_power = chi;

        for ((x, x_mac), (y, y_mac), (_z, z_mac)) in triples
            .iter()
            .map(|(x, y, z)| (x.decompose(), y.decompose(), z.decompose()))
        {
            let a0 = x_mac * y_mac;
            let a1 = y * x_mac + x * y_mac - z_mac;

            sum_a0 += a0 * chi_power;
            sum_a1 += a1 * chi_power;

            chi_power *= chi;
        }

        // The following block implements VOPE(1)
        let mut mask = T::ZERO;
        let mut mask_mac = T::ZERO;

        for i in 0..DegreeModulo::<V, T>::USIZE {
            let u = self.random(channel, rng)?;
            let x_i: T = make_x_i::<V, T>(i);
            mask += u.value() * x_i;
            mask_mac += u.mac() * x_i;
        }

        let u = sum_a0 + mask_mac;
        let v = sum_a1 + mask;

        channel.write_serializable(&u)?;
        channel.write_serializable(&v)?;
        channel.flush()?;

        Ok(())
    }

    /// Accumulate multiplication triple into state.
    pub fn quicksilver_accumulate(
        &mut self,
        state: &mut StateMultCheckProver<T>,
        triple: &(MacProver<V, T>, MacProver<V, T>, MacProver<V, T>),
    ) -> Result<()> {
        debug!("quicksilver_push");
        let (x, y, z) = triple;
        let a0 = x.mac() * y.mac();
        let a1 = y.value() * x.mac() + x.value() * y.mac() - z.mac();

        state.sum_a0 += a0 * state.chi_power;
        state.sum_a1 += a1 * state.chi_power;
        state.chi_power *= state.chi;
        state.cnt += 1;

        Ok(())
    }

    /// Finalize the multiplication check for a state return how many triples were checked.
    pub fn quicksilver_finalize<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        state: &mut StateMultCheckProver<T>,
    ) -> Result<usize> {
        debug!("quicksilver_finalize");
        // The following block implements VOPE(1)
        let mut mask = T::ZERO;
        let mut mask_mac = T::ZERO;

        for i in 0..DegreeModulo::<V, T>::USIZE {
            let u = self.random(channel, rng)?;
            let x_i: T = make_x_i::<V, T>(i);
            mask += u.value() * x_i;
            mask_mac += u.mac() * x_i;
        }

        let u = state.sum_a0 + mask_mac;
        let v = state.sum_a1 + mask;

        channel.write_serializable(&u)?;
        channel.write_serializable(&v)?;
        channel.flush()?;
        let c = state.cnt;
        state.reset();
        Ok(c)
    }
}

/// Homomorphic commitment scheme from the verifier's point-of-view.
pub struct FComVerifier<V: IsSubFieldOf<T>, T: FiniteField, VOLE: SvoleT<T>>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    delta: T,
    svole_receiver: VOLE,
    voles: Vec<T>,
    phantom: PhantomData<V>,
}

/// State to accumulate multiplication checks.
pub struct StateMultCheckVerifier<T> {
    sum_b: T,
    power_chi: T,
    chi: T,
    cnt: usize,
}

impl<T> Drop for StateMultCheckVerifier<T> {
    fn drop(&mut self) {
        if self.cnt != 0 {
            warn!(
                "Quicksilver functionality dropped before check finished, mult cnt {:?}",
                self.cnt
            );
        }
    }
}

impl<T: FiniteField> StateMultCheckVerifier<T> {
    /// Initialize the state.
    pub fn init<C: AbstractChannel>(channel: &mut C, rng: &mut AesRng) -> Result<Self> {
        let chi = T::random(rng);
        channel.write_serializable::<T>(&chi)?;
        channel.flush()?;

        Ok(StateMultCheckVerifier {
            sum_b: T::ZERO,
            power_chi: chi,
            chi,
            cnt: 0,
        })
    }

    /// Reset the state.
    fn reset(&mut self) {
        self.sum_b = T::ZERO;
        self.power_chi = self.chi;
        self.cnt = 0;
    }

    /// Return the number of checks accumulated.
    pub fn count(&self) -> usize {
        self.cnt
    }
}

/// State to accumulate check zero.
pub struct StateZeroCheckVerifier<T> {
    rng: AesRng,
    key_chi: T,
    cnt: usize,
}

impl<T> Drop for StateZeroCheckVerifier<T> {
    fn drop(&mut self) {
        if self.cnt != 0 {
            warn!(
                "State for check_zero dropped before check finished, cnt: {:?}",
                self.cnt
            );
        }
    }
}

impl<T: FiniteField> StateZeroCheckVerifier<T> {
    /// Initialize the state.
    pub fn init<C: AbstractChannel>(channel: &mut C, rng: &mut AesRng) -> Result<Self> {
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let rng = AesRng::from_seed(seed);

        Ok(StateZeroCheckVerifier {
            rng,
            key_chi: T::ZERO,
            cnt: 0,
        })
    }

    /// Reset the state.
    pub fn reset(&mut self) {
        // After reset, we assume the internal rng is still synchronized between the prover and the verifier.
        self.key_chi = T::ZERO;
        self.cnt = 0;
    }

    /// Return the number of checks accumulated.
    pub fn count(&self) -> usize {
        self.cnt
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField, VOLE: SvoleT<T>> FComVerifier<V, T, VOLE>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize the commitment scheme.
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        let recv = VOLE::init(channel, rng, lpn_setup, lpn_extend)?;
        Ok(Self {
            delta: recv.delta().unwrap(),
            svole_receiver: recv,
            voles: Vec::new(),
            phantom: PhantomData,
        })
    }

    pub fn init_with_vole(vole: VOLE) -> Result<Self> {
        Ok(Self {
            delta: vole.delta().unwrap(), // That's going to block until delta is set
            svole_receiver: vole,
            voles: Vec::new(),
            phantom: PhantomData,
        })
    }

    /// Duplicate the commitment scheme.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            delta: self.get_delta(),
            svole_receiver: self.svole_receiver.duplicate(),
            voles: Vec::new(),
            phantom: PhantomData,
        })
    }

    /// Return the `Δ` value associated with the commitment scheme.
    #[inline]
    pub fn get_delta(&self) -> T {
        self.delta
    }

    /// Return a random [`MacVerifier`].
    pub fn random<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<MacVerifier<T>> {
        match self.voles.pop() {
            Some(e) => Ok(MacVerifier::new(e)),
            None => {
                self.svole_receiver.extend(channel, rng, &mut self.voles)?;
                match self.voles.pop() {
                    Some(e) => Ok(MacVerifier::new(e)),
                    None => Err(eyre!("svole failed for random")),
                }
            }
        }
    }

    /// Input a number of commitment values and return the associated MACs.
    // TODO: should we remove this and just use `input_low_level`.
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

    /// Implementation of `input` with a pre-defined output vector.
    pub fn input_low_level<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
        out: &mut Vec<MacVerifier<T>>,
    ) -> Result<()> {
        for _i in 0..num {
            let r = self.random(channel, rng)?;
            let y = channel.read_serializable::<V>()?;
            out.push(MacVerifier::new(r.mac() - y * self.delta));
        }
        Ok(())
    }

    /// Input a single value and returns its MAC.
    pub fn input1<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<MacVerifier<T>> {
        let r = self.random(channel, rng)?;
        let y = channel.read_serializable::<V>()?;
        let out = MacVerifier::new(r.mac() - y * self.delta);
        Ok(out)
    }

    /// Add a constant.
    // TODO: Should these be method on `MacVerifier` instead?
    #[inline]
    pub fn affine_add_cst(&self, cst: V, x: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier::new(x.mac() - cst * self.delta)
    }

    /// Multiply by a constant.
    #[inline]
    pub fn affine_mult_cst(&self, cst: V, x: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier::new(cst * x.mac())
    }

    /// Add two [`MacVerifier`]s.
    #[inline]
    pub fn add(&self, a: MacVerifier<T>, b: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier::new(a.mac() + b.mac())
    }

    /// Negate a [`MacVerifier`].
    #[inline]
    pub fn neg(&self, a: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier::new(-a.mac())
    }

    /// Subtract two [`MacVerifier`]s.
    #[inline]
    pub fn sub(&self, a: MacVerifier<T>, b: MacVerifier<T>) -> MacVerifier<T> {
        MacVerifier::new(a.mac() - b.mac())
    }

    /// Check that a batch of [`MacVerifier`]s are zero.
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
        for key in key_batch.iter() {
            let chi = T::random(&mut rng);
            key_chi += chi * key.mac();
        }
        let m = channel.read_serializable::<T>()?;

        let b = key_chi == m;

        if b {
            Ok(())
        } else {
            Err(eyre!("check_zero failed"))
        }
    }

    /// Accumulate a value to zero check into a state.
    pub fn check_zero_accumulate(
        &mut self,
        key: &MacVerifier<T>,
        state: &mut StateZeroCheckVerifier<T>,
    ) -> Result<()> {
        let chi = T::random(&mut state.rng);
        state.key_chi += chi * key.mac();
        state.cnt += 1;
        Ok(())
    }

    /// Finalize check zero of a state and return how many values were checked.
    pub fn check_zero_finalize<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        state: &mut StateZeroCheckVerifier<T>,
    ) -> Result<usize> {
        let m = channel.read_serializable::<T>()?;

        let b = state.key_chi == m;
        let cnt = state.cnt;
        state.reset();
        ensure!(b, "check zero failed");
        Ok(cnt)
    }

    /// Open a batch of [`MacVerifier`]s.
    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        keys: &[MacVerifier<T>],
        out: &mut Vec<V>,
    ) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        out.clear();
        for _ in 0..keys.len() {
            let x = channel.read_serializable::<V>()?;
            out.push(x);
            hasher.update(&x.to_bytes());
        }
        let seed = Block::try_from_slice(&hasher.finalize().as_bytes()[0..16]).unwrap();
        let mut rng = AesRng::from_seed(seed);

        let mut key_chi = T::ZERO;
        let mut x_chi = T::ZERO;
        for i in 0..keys.len() {
            let chi = T::random(&mut rng);
            let x = out[i];

            key_chi += chi * keys[i].mac();
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

        for (x, y, z) in triples.iter() {
            //  should be `- (-delta)` with our conventions compared to
            //  quicksilver but simplified out.
            let b = (x.mac()) * (y.mac()) + self.delta * z.mac();

            sum_b += b * power_chi;
            power_chi *= chi;
        }

        // The following block implements VOPE(1)
        let mut mask_mac = T::ZERO;
        for i in 0..DegreeModulo::<V, T>::USIZE {
            let v = self.random(channel, rng)?;
            let x_i: T = make_x_i::<V, T>(i);
            mask_mac += v.mac() * x_i;
        }

        let u = channel.read_serializable::<T>()?;
        let v = channel.read_serializable::<T>()?;

        let b_plus = sum_b + mask_mac;
        if b_plus == (u + (-self.delta) * v) {
            // - because of delta
            Ok(())
        } else {
            bail!("QuickSilver multiplication check failed.")
        }
    }

    /// Accumulate multiplication triple into state.
    pub fn quicksilver_accumulate(
        &mut self,
        state: &mut StateMultCheckVerifier<T>,
        triple: &(MacVerifier<T>, MacVerifier<T>, MacVerifier<T>),
    ) -> Result<()> {
        let (x, y, z) = triple;
        //  should be `- (-delta)` with our conventions compared to
        //  quicksilver but simplified out.
        let b = (x.mac()) * (y.mac()) + self.delta * z.mac();

        state.sum_b += b * state.power_chi;
        state.power_chi *= state.chi;
        state.cnt += 1;
        Ok(())
    }

    /// Finalize the multiplication check for a state return how many triples were checked.
    pub fn quicksilver_finalize<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        state: &mut StateMultCheckVerifier<T>,
    ) -> Result<usize> {
        // The following block implements VOPE(1)
        let mut mask_mac = T::ZERO;
        for i in 0..DegreeModulo::<V, T>::USIZE {
            let v = self.random(channel, rng)?;
            let x_i: T = make_x_i::<V, T>(i);
            mask_mac += v.mac() * x_i;
        }

        let u = channel.read_serializable::<T>()?;
        let v = channel.read_serializable::<T>()?;

        let b_plus = state.sum_b + mask_mac;
        if b_plus == (u + (-self.delta) * v) {
            // - because of delta
            let c = state.cnt;
            state.reset();
            Ok(c)
        } else {
            state.reset();
            bail!("QuickSilver multiplication check failed.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FComProver, FComVerifier, MacProver};
    use crate::svole_thread::{SvoleAtomic, ThreadReceiver, ThreadSender};
    use crate::svole_trait::{SvoleReceiver, SvoleSender, SvoleT};
    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::SeedableRng;
    use scuttlebutt::{
        field::{F40b, F61p, FiniteField, IsSubFieldOf, F2},
        AbstractChannel, AesRng, Channel, SyncChannel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_fcom_random<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<V, T, SvoleSender<T>>::init(
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
        let mut fcom = FComVerifier::<V, T, SvoleReceiver<V, T>>::init(
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
            assert_eq!(r[i], resprover[i].value());
        }
    }

    fn test_fcom_affine<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 200;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<V, T, SvoleSender<T>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.random(&mut channel, &mut rng).unwrap();
                let cst = V::random(&mut rng);
                channel.write_serializable::<V>(&cst).unwrap();
                channel.flush().unwrap();
                let m = fcom.affine_mult_cst(cst, x);
                v.push(m);
                let a = fcom.affine_add_cst(cst, x);
                v.push(a);
            }
            fcom.open(&mut channel, &v).unwrap();
            v
        });
        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComVerifier::<V, T, SvoleReceiver<V, T>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let x_mac = fcom.random(&mut channel, &mut rng).unwrap();
            let cst = channel.read_serializable::<V>().unwrap();
            let m_mac = fcom.affine_mult_cst(cst, x_mac);
            v.push(m_mac);
            let a_mac = fcom.affine_add_cst(cst, x_mac);
            v.push(a_mac);
        }

        let mut r = Vec::new();
        fcom.open(&mut channel, &v, &mut r).unwrap();

        let batch_prover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], batch_prover[i].value());
        }
    }

    fn test_fcom_multiplication<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<V, T, SvoleSender<T>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.random(&mut channel, &mut rng).unwrap();
                let y = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x.value() * y.value();
                let z_mac = fcom.input(&mut channel, &mut rng, &[z]).unwrap()[0];
                v.push((x, y, MacProver::new(z, z_mac)));
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
        let mut fcom = FComVerifier::<V, T, SvoleReceiver<V, T>>::init(
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

    fn test_fcom_check_zero<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComProver::<V, T, SvoleSender<T>>::init(
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
                    let x = V::ZERO;
                    let xmac = fcom.input1(&mut channel, &mut rng, x).unwrap();
                    v.push(MacProver::new(x, xmac));
                }
                channel.flush().unwrap();
                let r = fcom.check_zero(&mut channel, v.as_slice());
                assert!(r.is_ok());
            }

            for n in 1..count {
                // NON_ZERO
                let mut v = Vec::new();
                for _ in 0..n {
                    let x = V::random_nonzero(&mut rng);
                    let xmac = fcom.input1(&mut channel, &mut rng, x).unwrap();
                    v.push(MacProver::new(x, xmac));
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
        let mut fcom = FComVerifier::<V, T, SvoleReceiver<V, T>>::init(
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

    fn test_fcom_multiplication_multithreaded<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 50;
        let (sender_vole, receiver_vole) = UnixStream::pair().unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender_vole.try_clone().unwrap());
            let writer = BufWriter::new(sender_vole);
            let mut channel_vole = SyncChannel::new(reader, writer);

            let svole_atomic = SvoleAtomic::<(V, T)>::create();
            let svole_atomic2 = svole_atomic.duplicate();

            let _svole_thread = std::thread::spawn(move || {
                let mut svole_prover = ThreadSender::<V, T>::init(
                    &mut channel_vole,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                    svole_atomic2,
                )
                .unwrap();
                svole_prover.run(&mut channel_vole, &mut rng).unwrap();
            });

            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut fcom =
                FComProver::<V, T, SvoleAtomic<(V, T)>>::init_with_vole(svole_atomic).unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.random(&mut channel, &mut rng).unwrap();
                let y = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x.value() * y.value();
                let z_mac = fcom.input(&mut channel, &mut rng, &[z]).unwrap()[0];
                v.push((x, y, MacProver::new(z, z_mac)));
            }
            channel.flush().unwrap();
            fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
                .unwrap();
            v
        });
        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver_vole.try_clone().unwrap());
        let writer = BufWriter::new(receiver_vole);
        let mut channel_vole = SyncChannel::new(reader, writer);

        let svole_atomic = SvoleAtomic::<T>::create();
        let svole_atomic2 = svole_atomic.duplicate();

        let _svole_thread = std::thread::spawn(move || {
            let mut svole_receiver = ThreadReceiver::<V, T>::init(
                &mut channel_vole,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                svole_atomic2,
            )
            .unwrap();
            svole_receiver.run(&mut channel_vole, &mut rng).unwrap();
        });

        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut fcom = FComVerifier::<V, T, SvoleAtomic<T>>::init_with_vole(svole_atomic).unwrap();

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

    #[test]
    fn test_fcom_f61p() {
        test_fcom_random::<F61p, F61p>();

        test_fcom_affine::<F61p, F61p>();
        test_fcom_multiplication::<F61p, F61p>();
        test_fcom_check_zero::<F61p, F61p>();
    }

    #[test]
    fn test_fcom_f2_f40b() {
        test_fcom_random::<F2, F40b>();
        test_fcom_affine::<F2, F40b>();
        test_fcom_multiplication::<F2, F40b>();
        test_fcom_check_zero::<F2, F40b>();
    }

    #[test]
    fn test_fcom_f40b_f40b() {
        test_fcom_random::<F40b, F40b>();
        test_fcom_affine::<F40b, F40b>();
        test_fcom_multiplication::<F40b, F40b>();
        test_fcom_check_zero::<F40b, F40b>();
    }

    #[test]
    fn test_fcom_singlethread_multiplication() {
        test_fcom_multiplication::<F61p, F61p>();
    }

    #[test]
    fn test_fcom_multithreaded() {
        test_fcom_multiplication_multithreaded::<F61p, F61p>();
    }
}
