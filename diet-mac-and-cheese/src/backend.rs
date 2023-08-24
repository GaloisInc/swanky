use crate::backend_trait::{BackendT, Party};
use crate::homcom::{
    FComProver, FComVerifier, MacProver, MacVerifier, StateMultCheckProver, StateMultCheckVerifier,
};
use eyre::{eyre, Result};
use log::{debug, info, warn};
use ocelot::svole::LpnParams;
use scuttlebutt::{AbstractChannel, AesRng};
use swanky_field::{FiniteField, IsSubFieldOf};

// Some design decisions:
// * There is one queue for the multiplication check and another queue for `assert_zero`s.
// * The communication during circuit evaluation goes from the prover to the verifier,
//   therefore it is possible to flush only when queues are full and mult or zero checks are performed.
// * Gates do not specifiy whether their input values are public or private, their execution
//   does a case analysis to perform the right operation.
//   For example, a multiplication with public values requires a simple field multiplication,
//   whereas the input are private it requires a zero_knowledge multiplication check.

const QUEUE_CAPACITY: usize = 3_000_000;
const TICK_TIMER: usize = 5_000_000;

#[derive(Default)]
struct Monitor {
    tick: usize,
    monitor_instance: usize,
    monitor_witness: usize,
    monitor_mul: usize,
    monitor_mulc: usize,
    monitor_add: usize,
    monitor_sub: usize,
    monitor_addc: usize,
    monitor_check_zero: usize,
    monitor_zk_check_zero: usize,
    monitor_zk_mult_check: usize,
}

impl Monitor {
    fn tick(&mut self) {
        self.tick += 1;
        if self.tick >= TICK_TIMER {
            self.tick %= TICK_TIMER;
            self.log_monitor();
        }
    }

    fn incr_monitor_instance(&mut self) {
        self.tick();
        self.monitor_instance += 1;
    }
    fn incr_monitor_mul(&mut self) {
        self.tick();
        self.monitor_mul += 1;
    }
    fn incr_monitor_mulc(&mut self) {
        self.tick();
        self.monitor_mulc += 1;
    }
    fn incr_monitor_add(&mut self) {
        self.tick();
        self.monitor_add += 1;
    }
    fn incr_monitor_sub(&mut self) {
        self.tick();
        self.monitor_sub += 1;
    }
    fn incr_monitor_addc(&mut self) {
        self.tick();
        self.monitor_addc += 1;
    }
    fn incr_monitor_check_zero(&mut self) {
        self.tick();
        self.monitor_check_zero += 1;
    }
    fn incr_monitor_witness(&mut self) {
        self.tick();
        self.monitor_witness += 1;
    }

    fn incr_zk_mult_check(&mut self, n: usize) {
        self.monitor_zk_mult_check += n;
    }
    fn incr_zk_check_zero(&mut self, n: usize) {
        self.monitor_zk_check_zero += n;
    }

    fn log_monitor(&self) {
        info!(
            "inp:{:<11} witn:{:<11} mul:{:<11} czero:{:<11}",
            self.monitor_instance, self.monitor_witness, self.monitor_mul, self.monitor_check_zero,
        );
    }

    fn log_final_monitor(&self) {
        if self.monitor_mul != self.monitor_zk_mult_check {
            warn!(
                "diff numb of mult gates {} and mult_check {}",
                self.monitor_mul, self.monitor_zk_mult_check
            );
        }

        info!("nb inst:   {:>11}", self.monitor_instance);
        info!("nb witn:   {:>11}", self.monitor_witness);
        info!("nb addc:   {:>11}", self.monitor_addc);
        info!("nb add:    {:>11}", self.monitor_add);
        info!("nb sub:    {:>11}", self.monitor_sub);
        info!("nb multc:  {:>11}", self.monitor_mulc);
        info!("nb mult:   {:>11}", self.monitor_mul);
        info!("nb czero:  {:>11}", self.monitor_check_zero);
    }
}

/// Prover for Diet Mac'n'Cheese.
pub struct DietMacAndCheeseProver<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    is_ok: bool,
    pub(crate) prover: FComProver<V, T>,
    pub(crate) channel: C,
    pub(crate) rng: AesRng,
    check_zero_list: Vec<MacProver<V, T>>,
    monitor: Monitor,
    state_mult_check: StateMultCheckProver<T>,
    no_batching: bool,
}

impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel> BackendT
    for DietMacAndCheeseProver<V, T, C>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    type Wire = MacProver<V, T>;
    type FieldElement = V;

    fn party(&self) -> Party {
        Party::Prover
    }
    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement> {
        Some(wire.value())
    }

    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        Ok(wire.clone())
    }

    fn random(&mut self) -> Result<Self::FieldElement> {
        self.channel.flush()?;
        let challenge = self.channel.read_serializable::<Self::FieldElement>()?;
        Ok(challenge)
    }

    fn one(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ONE)
    }

    fn zero(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.input_public(val)
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_check_zero();
        self.push_check_zero_list(*wire)
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_add();
        Ok(self.prover.add(*a, *b))
    }

    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_sub();
        Ok(self.prover.sub(*a, *b))
    }

    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mul();
        let a_clr = a.value();
        let b_clr = b.value();
        let product = a_clr * b_clr;

        let out = self.input(product)?;
        self.prover
            .quicksilver_push(&mut self.state_mult_check, &(*a, *b, out))?;
        Ok(out)
    }

    fn add_constant(
        &mut self,
        value: &Self::Wire,
        constant: Self::FieldElement,
    ) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_addc();
        Ok(self.prover.affine_add_cst(constant, *value))
    }

    fn mul_constant(
        &mut self,
        value: &Self::Wire,
        constant: Self::FieldElement,
    ) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mulc();
        Ok(self.prover.affine_mult_cst(constant, *value))
    }

    fn input_public(&mut self, value: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_instance();
        Ok(MacProver::new(value, T::ZERO))
    }

    fn input_private(&mut self, value: Option<Self::FieldElement>) -> Result<Self::Wire> {
        if let Some(value) = value {
            self.check_is_ok()?;
            self.monitor.incr_monitor_witness();
            self.input(value)
        } else {
            Err(eyre!("No private input given to the prover"))
        }
    }

    fn finalize(&mut self) -> Result<()> {
        debug!("finalize");
        self.check_is_ok()?;
        self.channel.flush()?;
        let zero_len = self.check_zero_list.len();
        self.do_check_zero()?;

        let mult_len = self.do_mult_check()?;
        debug!(
            "finalize: mult_check:{:?}, check_zero:{:?} ",
            mult_len, zero_len
        );
        self.log_final_monitor();
        Ok(())
    }
    fn reset(&mut self) {
        self.prover.reset(&mut self.state_mult_check);
        self.is_ok = true;
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel> DietMacAndCheeseProver<V, T, C>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize the prover by providing a channel, a random generator and a pair of LPN parameters as defined by svole.
    pub fn init(
        channel: &mut C,
        mut rng: AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let state_mult_check = StateMultCheckProver::init(channel)?;
        Ok(Self {
            is_ok: true,
            prover: FComProver::init(channel, &mut rng, lpn_setup, lpn_extend)?,
            channel: channel.clone(),
            rng,
            check_zero_list: Vec::new(),
            monitor: Monitor::default(),
            state_mult_check,
            no_batching,
        })
    }

    /// Initialize the verifier by providing a reference to a fcom.
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        rng: AesRng,
        fcom: &FComProver<V, T>,
        no_batching: bool,
    ) -> Result<Self> {
        let state_mult_check = StateMultCheckProver::init(channel)?;
        Ok(Self {
            is_ok: true,
            prover: fcom.duplicate()?,
            channel: channel.clone(),
            rng,
            check_zero_list: Vec::new(),
            monitor: Monitor::default(),
            state_mult_check,
            no_batching,
        })
    }

    /// Get party
    pub(crate) fn get_party(&self) -> &FComProver<V, T> {
        &self.prover
    }

    // this function should be called before every function exposed publicly by the API.
    fn check_is_ok(&self) -> Result<()> {
        if self.is_ok {
            Ok(())
        } else {
            Err(eyre!(
                "An error occurred earlier. This functionality should not be used further"
            ))
        }
    }

    fn input(&mut self, v: V) -> Result<MacProver<V, T>> {
        let tag = self.prover.input1(&mut self.channel, &mut self.rng, v);
        if tag.is_err() {
            self.is_ok = false;
        }
        Ok(MacProver::new(v, tag?))
    }

    fn do_mult_check(&mut self) -> Result<usize> {
        debug!("do mult_check");
        self.channel.flush()?;
        let cnt = self.prover.quicksilver_finalize(
            &mut self.channel,
            &mut self.rng,
            &mut self.state_mult_check,
        )?;
        self.monitor.incr_zk_mult_check(cnt);
        Ok(cnt)
    }

    fn do_check_zero(&mut self) -> Result<()> {
        // debug!("do check_zero");
        self.channel.flush()?;
        let r = self
            .prover
            .check_zero(&mut self.channel, &self.check_zero_list);
        if r.is_err() {
            warn!("check_zero fails");
            self.is_ok = false;
        }
        self.monitor.incr_zk_check_zero(self.check_zero_list.len());
        self.check_zero_list.clear();
        r
    }

    fn push_check_zero_list(&mut self, e: MacProver<V, T>) -> Result<()> {
        self.check_zero_list.push(e);

        if self.check_zero_list.len() == QUEUE_CAPACITY || self.no_batching {
            self.do_check_zero()?;
        }
        Ok(())
    }

    fn log_final_monitor(&self) {
        info!("field largest value: {:?}", (T::ZERO - T::ONE).to_bytes());
        self.monitor.log_final_monitor();
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel> Drop
    for DietMacAndCheeseProver<V, T, C>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn drop(&mut self) {
        if self.is_ok && !self.check_zero_list.is_empty() {
            warn!("Dropped in unexpected state: either `finalize()` has not been called or an error occured earlier.");
        }
    }
}

/// Verifier for Diet Mac'n'Cheese.
pub struct DietMacAndCheeseVerifier<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    pub(crate) verifier: FComVerifier<V, T>,
    pub(crate) channel: C,
    pub(crate) rng: AesRng,
    check_zero_list: Vec<MacVerifier<T>>,
    monitor: Monitor,
    state_mult_check: StateMultCheckVerifier<T>,
    is_ok: bool,
    no_batching: bool,
}

impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel> BackendT
    for DietMacAndCheeseVerifier<V, T, C>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    type Wire = MacVerifier<T>;
    type FieldElement = V;

    fn party(&self) -> Party {
        Party::Verifier
    }
    fn wire_value(&self, _wire: &Self::Wire) -> Option<Self::FieldElement> {
        None
    }

    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        Ok(wire.clone())
    }

    fn random(&mut self) -> Result<Self::FieldElement> {
        let challenge = Self::FieldElement::random(&mut self.rng);
        self.channel.write_serializable(&challenge)?;
        self.channel.flush()?;
        Ok(challenge)
    }

    fn one(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ONE)
    }

    fn zero(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.input_public(val)
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_check_zero();
        self.push_check_zero_list(*wire)
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_add();
        Ok(self.verifier.add(*a, *b))
    }

    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_sub();
        Ok(self.verifier.sub(*a, *b))
    }

    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mul();
        let tag = self.input()?;
        self.verifier
            .quicksilver_push(&mut self.state_mult_check, &(*a, *b, tag))?;
        Ok(tag)
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_addc();
        Ok(self.verifier.affine_add_cst(b, *a))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mulc();
        Ok(self.verifier.affine_mult_cst(b, *a))
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_instance();
        Ok(MacVerifier::new(-val * self.get_party().get_delta()))
    }

    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        if val.is_some() {
            return Err(eyre!("Private input given to the verifier"));
        } else {
            self.check_is_ok()?;
            self.monitor.incr_monitor_witness();
            self.input()
        }
    }

    fn finalize(&mut self) -> Result<()> {
        debug!("finalize");
        self.check_is_ok()?;
        self.channel.flush()?;
        let zero_len = self.check_zero_list.len();
        self.do_check_zero()?;

        let mult_len = self.do_mult_check()?;
        debug!(
            "finalize: mult_check:{:?}, check_zero:{:?} ",
            mult_len, zero_len
        );
        self.log_final_monitor();
        Ok(())
    }

    fn reset(&mut self) {
        self.verifier.reset(&mut self.state_mult_check);
        self.is_ok = true;
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel> DietMacAndCheeseVerifier<V, T, C>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize the verifier by providing a channel, a random generator and a pair of LPN parameters as defined by svole.
    pub fn init(
        channel: &mut C,
        mut rng: AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let state_mult_check = StateMultCheckVerifier::init(channel, &mut rng)?;
        Ok(Self {
            verifier: FComVerifier::init(channel, &mut rng, lpn_setup, lpn_extend)?,
            channel: channel.clone(),
            rng,
            check_zero_list: Vec::with_capacity(QUEUE_CAPACITY),
            monitor: Monitor::default(),
            state_mult_check,
            is_ok: true,
            no_batching,
        })
    }

    /// Initialize the verifier by providing a reference to a fcom.
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        mut rng: AesRng,
        fcom: &FComVerifier<V, T>,
        no_batching: bool,
    ) -> Result<Self> {
        let state_mult_check = StateMultCheckVerifier::init(channel, &mut rng)?;
        Ok(Self {
            is_ok: true,
            verifier: fcom.duplicate()?,
            channel: channel.clone(),
            rng,
            check_zero_list: Vec::with_capacity(QUEUE_CAPACITY),
            monitor: Monitor::default(),
            state_mult_check,
            no_batching,
        })
    }

    /// Get party
    pub(crate) fn get_party(&self) -> &FComVerifier<V, T> {
        &self.verifier
    }

    // this function should be called before every function exposed publicly by the API.
    fn check_is_ok(&self) -> Result<()> {
        if !self.is_ok {
            return Err(eyre!(
                "An error occurred earlier. This functionality should not be used further"
            ));
        }
        Ok(())
    }

    fn input(&mut self) -> Result<MacVerifier<T>> {
        let tag = self.verifier.input1(&mut self.channel, &mut self.rng);
        if tag.is_err() {
            self.is_ok = false;
        }
        tag
    }

    fn do_mult_check(&mut self) -> Result<usize> {
        debug!("do mult_check");
        self.channel.flush()?;
        let cnt = self.verifier.quicksilver_finalize(
            &mut self.channel,
            &mut self.rng,
            &mut self.state_mult_check,
        )?;
        self.monitor.incr_zk_mult_check(cnt);
        Ok(cnt)
    }

    fn do_check_zero(&mut self) -> Result<()> {
        // debug!("do check_zero");
        self.channel.flush()?;
        let r = self
            .verifier
            .check_zero(&mut self.channel, &mut self.rng, &self.check_zero_list);
        if r.is_err() {
            warn!("check_zero fails");
            self.is_ok = false;
        }
        self.monitor.incr_zk_check_zero(self.check_zero_list.len());
        self.check_zero_list.clear();
        r
    }

    fn push_check_zero_list(&mut self, e: MacVerifier<T>) -> Result<()> {
        self.check_zero_list.push(e);

        if self.check_zero_list.len() == QUEUE_CAPACITY || self.no_batching {
            self.do_check_zero()?;
        }
        Ok(())
    }

    fn log_final_monitor(&self) {
        info!("field largest value: {:?}", (T::ZERO - T::ONE).to_bytes());
        self.monitor.log_final_monitor();
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel> Drop
    for DietMacAndCheeseVerifier<V, T, C>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn drop(&mut self) {
        if self.is_ok && !self.check_zero_list.is_empty() {
            warn!("Dropped in unexpected state: either `finalize()` has not been called or an error occured earlier.");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        backend::{DietMacAndCheeseProver, DietMacAndCheeseVerifier},
        backend_trait::BackendT,
        homcom::validate,
    };
    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::SeedableRng;
    use scuttlebutt::field::{F40b, IsSubFieldOf, F2};
    use scuttlebutt::{
        field::{F61p, FiniteField},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut dmc: DietMacAndCheeseProver<V, T, _> = DietMacAndCheeseProver::init(
                &mut channel,
                rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )
            .unwrap();

            // one1        = public(1)
            // one2        = public(1)
            // two_pub     = add(one1, one2)
            // three_pub   = addc(two_pub, 1)
            // two_priv    = priv(2)
            // six         = mul(two_priv, three_pub)
            // twelve_priv = mulc(six, 2)
            // n24_priv    = mul(twelve_priv, two_priv)
            // r_zero_priv = addc(n24_priv, -24)
            // assert_zero(r_zero_priv)
            // assert_zero(n24_priv) !!!!FAIL!!!!!
            let one = V::ONE;
            let two = one + one;
            let three = two + one;
            let one1 = dmc.input_public(one).unwrap();
            let one2 = dmc.input_public(one).unwrap();
            let two_pub = dmc.add(&one1, &one2).unwrap();
            assert_eq!(two_pub, dmc.input_public(two).unwrap());
            let three_pub = dmc.add_constant(&two_pub, one).unwrap();
            assert_eq!(three_pub, dmc.input_public(three).unwrap());
            let two_priv = dmc.input_private(Some(two)).unwrap();
            let six = dmc.mul(&two_priv, &three_pub).unwrap();
            let twelve_priv = dmc.mul_constant(&six, two).unwrap();
            assert_eq!(twelve_priv.value(), three * two * two);
            let n24_priv = dmc.mul(&twelve_priv, &two_priv).unwrap();
            let r_zero_priv = dmc
                .add_constant(&n24_priv, -(three * two * two * two))
                .unwrap();
            dmc.assert_zero(&r_zero_priv).unwrap();
            dmc.finalize().unwrap();
            dmc.assert_zero(&n24_priv).unwrap();
            assert!(dmc.finalize().is_err());
        });

        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut dmc: DietMacAndCheeseVerifier<V, T, _> = DietMacAndCheeseVerifier::init(
            &mut channel,
            rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )
        .unwrap();

        let one = V::ONE;
        let two = one + one;
        let three = two + one;
        let one1 = dmc.input_public(one).unwrap();
        let one2 = dmc.input_public(one).unwrap();
        let two_pub = dmc.add(&one1, &one2).unwrap();
        let three_pub = dmc.add_constant(&two_pub, one).unwrap();
        let two_priv = dmc.input_private(None).unwrap();
        let six = dmc.mul(&two_priv, &three_pub).unwrap();
        let twelve_priv = dmc.mul_constant(&six, two).unwrap();
        let n24_priv = dmc.mul(&twelve_priv, &two_priv).unwrap();
        let r_zero_priv = dmc
            .add_constant(&n24_priv, -(three * two * two * two))
            .unwrap();
        dmc.assert_zero(&r_zero_priv).unwrap();
        dmc.finalize().unwrap();
        dmc.assert_zero(&n24_priv).unwrap();
        assert!(dmc.finalize().is_err());

        handle.join().unwrap();
    }

    fn test_challenge<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut dmc: DietMacAndCheeseProver<V, T, _> = DietMacAndCheeseProver::init(
                &mut channel,
                rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )
            .unwrap();

            let challenge = dmc.random().unwrap();
            let challenge = dmc.input_public(challenge).unwrap();

            dmc.finalize().unwrap();

            challenge
        });

        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut dmc: DietMacAndCheeseVerifier<V, T, _> = DietMacAndCheeseVerifier::init(
            &mut channel,
            rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )
        .unwrap();

        let challenge = dmc.random().unwrap();
        let verifier = dmc.input_public(challenge).unwrap();
        dmc.finalize().unwrap();

        let prover = handle.join().unwrap();
        assert!(validate(prover, verifier, dmc.get_party().get_delta()));
    }

    #[test]
    fn test_f61p() {
        test::<F61p, F61p>();
    }

    #[test]
    fn test_challenge_f61p() {
        test_challenge::<F61p, F61p>();
    }

    #[test]
    fn test_challenge_f2_f40b() {
        test_challenge::<F2, F40b>();
    }

    #[test]
    fn test_challenge_f40b_f40b() {
        test_challenge::<F40b, F40b>();
    }
}
