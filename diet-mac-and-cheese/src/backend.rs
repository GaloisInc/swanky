use std::marker::PhantomData;

use crate::backend_trait::BackendT;
use crate::homcom::{FCom, MultCheckState, ZeroCheckState};
use crate::mac::Mac;
use crate::svole_trait::field_name;
use crate::svole_trait::SvoleT;
use eyre::{bail, Result};
use log::{debug, info, warn};
use ocelot::svole::LpnParams;
use scuttlebutt::{AbstractChannel, AesRng};
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::private::ProverPrivateCopy;
use swanky_party::{Party, WhichParty};

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
pub(crate) struct Monitor<T> {
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
    phantom: PhantomData<T>,
}

impl<T: FiniteField> Monitor<T> {
    fn tick(&mut self) {
        self.tick += 1;
        if self.tick >= TICK_TIMER {
            self.tick %= TICK_TIMER;
            self.log_monitor();
        }
    }

    pub(crate) fn incr_monitor_instance(&mut self) {
        self.tick();
        self.monitor_instance += 1;
    }
    pub(crate) fn incr_monitor_mul(&mut self) {
        self.tick();
        self.monitor_mul += 1;
    }
    pub(crate) fn incr_monitor_mulc(&mut self) {
        self.tick();
        self.monitor_mulc += 1;
    }
    pub(crate) fn incr_monitor_add(&mut self) {
        self.tick();
        self.monitor_add += 1;
    }
    pub(crate) fn incr_monitor_sub(&mut self) {
        self.tick();
        self.monitor_sub += 1;
    }
    pub(crate) fn incr_monitor_addc(&mut self) {
        self.tick();
        self.monitor_addc += 1;
    }
    pub(crate) fn incr_monitor_check_zero(&mut self) {
        self.tick();
        self.monitor_check_zero += 1;
    }
    pub(crate) fn incr_monitor_witness(&mut self) {
        self.tick();
        self.monitor_witness += 1;
    }

    pub(crate) fn incr_zk_mult_check(&mut self, n: usize) {
        self.monitor_zk_mult_check += n;
    }
    pub(crate) fn incr_zk_check_zero(&mut self, n: usize) {
        self.monitor_zk_check_zero += n;
    }

    pub(crate) fn log_monitor(&self) {
        info!(
            "field:{} inp:{:<11} witn:{:<11} mul:{:<11} czero:{:<11}",
            field_name::<T>(),
            self.monitor_instance,
            self.monitor_witness,
            self.monitor_mul,
            self.monitor_check_zero,
        );
    }

    pub(crate) fn log_final_monitor(&self) {
        info!("Monitor for field: {}", field_name::<T>());
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

/// Single-Field Diet Mac'n'Cheese.
pub struct DietMacAndCheese<
    P: Party,
    V: IsSubFieldOf<T>,
    T: FiniteField,
    C: AbstractChannel + Clone,
    SVOLE: SvoleT<P, V, T>,
> where
    T::PrimeField: IsSubFieldOf<V>,
{
    pub(crate) fcom: FCom<P, V, T, SVOLE>,
    pub(crate) channel: C,
    pub(crate) rng: AesRng,
    mult_check_state: MultCheckState<P, T>,
    zero_check_state: ZeroCheckState<P, T>,
    no_batching: bool,
    monitor: Monitor<T>,
}

impl<
        P: Party,
        V: IsSubFieldOf<T>,
        T: FiniteField,
        C: AbstractChannel + Clone,
        SVOLE: SvoleT<P, V, T>,
    > DietMacAndCheese<P, V, T, C, SVOLE>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize by providing a channel, a random generator, and a pair of LPN parameters as defined by SVOLE.
    pub fn init(
        channel: &mut C,
        mut rng: AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mult_check_state = MultCheckState::init(channel, &mut rng)?;
        let zero_check_state = ZeroCheckState::init(channel, &mut rng)?;
        Ok(Self {
            fcom: FCom::init(channel, &mut rng, lpn_setup, lpn_extend)?,
            channel: channel.clone(),
            rng,
            monitor: Monitor::default(),
            mult_check_state,
            zero_check_state,
            no_batching,
        })
    }

    /// Initialize by providing a reference to an FCom.
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        mut rng: AesRng,
        fcom: &FCom<P, V, T, SVOLE>,
        no_batching: bool,
    ) -> Result<Self> {
        let mult_check_state = MultCheckState::init(channel, &mut rng)?;
        let zero_check_state = ZeroCheckState::init(channel, &mut rng)?;
        Ok(Self {
            fcom: fcom.duplicate()?,
            channel: channel.clone(),
            rng,
            monitor: Monitor::default(),
            mult_check_state,
            zero_check_state,
            no_batching,
        })
    }

    pub(crate) fn init_with_delta(
        channel: &mut C,
        mut rng: AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
        delta: T,
    ) -> Result<Self> {
        let mult_check_state = MultCheckState::init(channel, &mut rng)?;
        let zero_check_state = ZeroCheckState::init(channel, &mut rng)?;
        Ok(Self {
            fcom: FCom::init_with_delta(channel, &mut rng, lpn_setup, lpn_extend, delta)?,
            channel: channel.clone(),
            rng,
            monitor: Monitor::default(),
            mult_check_state,
            zero_check_state,
            no_batching,
        })
    }

    /// "Lifts" a verifier operating over `(V, T)` into one operating over `(T, T)`.
    ///
    /// This enforces that the same `Δ` is shared between the old and new verifier.
    pub fn lift<VOLE2: SvoleT<P, T, T>>(
        &mut self,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<DietMacAndCheese<P, T, T, C, VOLE2>> {
        self.channel.flush()?;
        match P::WHICH {
            WhichParty::Prover(_) => DietMacAndCheese::<P, T, T, C, VOLE2>::init(
                &mut self.channel,
                self.rng.fork(),
                lpn_setup,
                lpn_extend,
                self.no_batching,
            ),
            WhichParty::Verifier(ev) => DietMacAndCheese::<P, T, T, C, VOLE2>::init_with_delta(
                &mut self.channel,
                self.rng.fork(),
                lpn_setup,
                lpn_extend,
                self.no_batching,
                self.fcom.get_delta().into_inner(ev),
            ),
        }
    }

    fn input(&mut self, v: ProverPrivateCopy<P, V>) -> Result<Mac<P, V, T>> {
        Ok(match P::WHICH {
            WhichParty::Prover(ev) => {
                let tag =
                    self.fcom
                        .input1_prover(ev, &mut self.channel, &mut self.rng, v.into_inner(ev));
                Mac::new(v, tag?)
            }
            WhichParty::Verifier(ev) => {
                self.fcom
                    .input1_verifier(ev, &mut self.channel, &mut self.rng)?
            }
        })
    }

    fn do_mult_check(&mut self) -> Result<usize> {
        debug!("do mult_check");
        self.channel.flush()?;
        let count = self.fcom.quicksilver_finalize(
            &mut self.channel,
            &mut self.rng,
            &mut self.mult_check_state,
        )?;
        self.monitor.incr_zk_mult_check(count);
        Ok(count)
    }

    fn do_check_zero(&mut self) -> Result<usize> {
        self.channel.flush()?;
        let count = self.zero_check_state.finalize(&mut self.channel)?;
        self.monitor.incr_zk_check_zero(count);
        Ok(count)
    }

    fn push_check_zero(&mut self, e: &Mac<P, V, T>) -> Result<()> {
        if self.no_batching {
            self.fcom
                .check_zero(&mut self.channel, &mut self.rng, &[*e])?;
            return Ok(());
        }

        self.zero_check_state.accumulate(e)?;

        if self.zero_check_state.count() == QUEUE_CAPACITY {
            self.do_check_zero()?;
        }

        Ok(())
    }

    fn log_final_monitor(&self) {
        self.monitor.log_final_monitor();
    }
}

impl<
        P: Party,
        V: IsSubFieldOf<T>,
        T: FiniteField,
        C: AbstractChannel + Clone,
        SVOLE: SvoleT<P, V, T>,
    > Drop for DietMacAndCheese<P, V, T, C, SVOLE>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn drop(&mut self) {
        if self.zero_check_state.count() != 0 || self.mult_check_state.count() != 0 {
            warn!("Dropped in unexpected state: either `finalize()` has not been called or an error occured earlier.");
        }
    }
}

impl<
        P: Party,
        V: IsSubFieldOf<T>,
        T: FiniteField,
        C: AbstractChannel + Clone,
        SVOLE: SvoleT<P, V, T>,
    > BackendT for DietMacAndCheese<P, V, T, C, SVOLE>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    type Wire = Mac<P, V, T>;
    type FieldElement = V;

    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement> {
        match P::WHICH {
            WhichParty::Prover(ev) => Some(wire.value().into_inner(ev)),
            WhichParty::Verifier(_) => None,
        }
    }

    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        Ok(*wire)
    }

    fn random(&mut self) -> Result<Self::FieldElement> {
        match P::WHICH {
            WhichParty::Prover(_) => {
                self.channel.flush()?;
                let challenge = self.channel.read_serializable::<Self::FieldElement>()?;
                Ok(challenge)
            }
            WhichParty::Verifier(_) => {
                let challenge = Self::FieldElement::random(&mut self.rng);
                self.channel.write_serializable(&challenge)?;
                self.channel.flush()?;
                Ok(challenge)
            }
        }
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
        self.monitor.incr_monitor_check_zero();
        self.push_check_zero(wire)?;
        Ok(())
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.monitor.incr_monitor_add();
        Ok(*a + *b)
    }

    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.monitor.incr_monitor_sub();
        Ok(*a - *b)
    }

    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.monitor.incr_monitor_mul();

        let out = match P::WHICH {
            WhichParty::Prover(ev) => {
                let a_clr = a.value().into_inner(ev);
                let b_clr = b.value().into_inner(ev);
                let product = a_clr * b_clr;

                self.input(ProverPrivateCopy::new(product))?
            }
            WhichParty::Verifier(ev) => self.input(ProverPrivateCopy::empty(ev))?,
        };

        self.mult_check_state
            .accumulate(&(*a, *b, out), self.fcom.get_delta());

        Ok(out)
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_addc();
        Ok(self.fcom.affine_add_cst(b, *a))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_mulc();
        Ok(*a * b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_instance();
        Ok(match P::WHICH {
            WhichParty::Prover(_) => Mac::new(ProverPrivateCopy::new(val), T::ZERO),
            WhichParty::Verifier(ev) => Mac::new(
                ProverPrivateCopy::empty(ev),
                -val * self.fcom.get_delta().into_inner(ev),
            ),
        })
    }

    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        match P::WHICH {
            WhichParty::Prover(_) => {
                if let Some(val) = val {
                    self.monitor.incr_monitor_witness();
                    self.input(ProverPrivateCopy::new(val))
                } else {
                    bail!("No private input given to the prover")
                }
            }
            WhichParty::Verifier(ev) => {
                if val.is_some() {
                    bail!("Private input given to the verifier")
                } else {
                    self.monitor.incr_monitor_witness();
                    self.input(ProverPrivateCopy::empty(ev))
                }
            }
        }
    }

    fn finalize(&mut self) -> Result<()> {
        debug!("finalize");
        self.channel.flush()?;
        let zero_check_count = self.do_check_zero()?;
        let mult_check_count = self.do_mult_check()?;
        debug!(
            "finalize: mult_check: {:?}, check_zero: {:?}",
            mult_check_count, zero_check_count
        );
        self.log_final_monitor();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::svole_trait::Svole;
    use crate::{backend::DietMacAndCheese, backend_trait::BackendT, mac::validate};
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
    use swanky_party::{Prover, Verifier, IS_PROVER, IS_VERIFIER};

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

            let mut dmc: DietMacAndCheese<Prover, V, T, _, Svole<_, _, _>> =
                DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
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
            assert_eq!(twelve_priv.value().into_inner(IS_PROVER), three * two * two);
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

        let mut dmc: DietMacAndCheese<Verifier, V, T, _, Svole<_, _, _>> =
            DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
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

            let mut dmc: DietMacAndCheese<Prover, V, T, _, Svole<_, _, _>> =
                DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
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

        let mut dmc: DietMacAndCheese<Verifier, V, T, _, Svole<_, _, _>> =
            DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
                .unwrap();

        let challenge = dmc.random().unwrap();
        let verifier = dmc.input_public(challenge).unwrap();
        dmc.finalize().unwrap();

        let prover = handle.join().unwrap();
        validate(
            prover,
            verifier,
            dmc.fcom.get_delta().into_inner(IS_VERIFIER),
        );
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
