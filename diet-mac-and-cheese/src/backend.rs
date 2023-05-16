use crate::error::{Error::*, Result};
use generic_array::{typenum::Unsigned, GenericArray};
use log::{debug, info, warn};
use ocelot::edabits::{FComProver, FComVerifier, MacProver, MacVerifier};
use ocelot::svole::wykw::LpnParams;
use ocelot::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::{field::FiniteField, AbstractChannel};

// Some design decisions:
// * There is one queue for the multiplication check and another queue for `assert_zero`s.
// * The communication during circuit evaluation goes from the prover to the verifier,
//   therefore it is possible to flush only when queues are full and mult or zero checks are performed.
// * Gates do not specifiy whether their input values are public or private, their execution
//   does a case analysis to perform the right operation.
//   For example, a multiplication with public values requires a simple field multiplication,
//   whereas the input are private it requires a zero_knowledge multiplication check.

// function adapted from the `mac-and-cheese-rfme` branch
fn padded_read<FE: FiniteField>(mut x: &[u8]) -> Result<FE> {
    // This assumes that finite field elements can be zero padded in their byte reprs. For prime
    // fields, this assumes that the byte representation is little-endian.
    while x.last() == Some(&0) {
        x = &x[0..x.len() - 1];
    }
    if x.len() > FE::ByteReprLen::USIZE {
        Err(BackendError("Invalid field element".into()))
    } else {
        let mut out = GenericArray::default();
        let size = x.len().min(FE::ByteReprLen::USIZE);
        out[0..size].copy_from_slice(&x[0..size]);
        // NOTE: the FE type doesn't require that from_bytes be little-endian. However, we
        // currently implement it that way for all fields.
        FE::from_bytes(&out).map_err(|_| BackendError("Invalid field element".into()))
    }
}

/// Converts a little-endian byte slice to a field element. The byte slice may be zero padded.
pub fn from_bytes_le<FE: FiniteField>(val: &[u8]) -> Result<FE> {
    padded_read(val)
}

const QUEUE_CAPACITY: usize = 3_000_000;
const TICK_TIMER: usize = 5_000_000;

#[derive(Default)]
struct Monitor {
    tick: usize,
    monitor_instance: usize,
    monitor_witness: usize,
    monitor_mul: usize,
    monitor_mul_ni: usize,
    monitor_mulc: usize,
    monitor_add: usize,
    monitor_add_ni: usize,
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
    fn incr_monitor_mul_ni(&mut self) {
        self.tick();
        self.monitor_mul_ni += 1;
    }
    fn incr_monitor_mulc(&mut self) {
        self.tick();
        self.monitor_mulc += 1;
    }
    fn incr_monitor_add(&mut self) {
        self.tick();
        self.monitor_add += 1;
    }
    fn incr_monitor_add_ni(&mut self) {
        self.tick();
        self.monitor_add_ni += 1;
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
            "inp:{:<11} witn:{:<11} mult:{:<11} czero:{:<11}",
            self.monitor_instance,
            self.monitor_witness,
            self.monitor_zk_mult_check,
            self.monitor_zk_check_zero,
        );
    }

    fn log_final_monitor(&self) {
        if self.monitor_mul - self.monitor_mul_ni != self.monitor_zk_mult_check {
            warn!(
                "diff numb of mult gates {} and mult_check {}",
                self.monitor_mul - self.monitor_mul_ni,
                self.monitor_zk_mult_check
            );
        }

        info!("nb tick:   {:>11}", self.tick);
        info!("nb inst:   {:>11}", self.monitor_instance);
        info!("nb witn:   {:>11}", self.monitor_witness);
        info!("nb addc:   {:>11}", self.monitor_addc);
        info!("nb add:    {:>11}", self.monitor_add);
        info!("nb addni:  {:>11}", self.monitor_add_ni);
        info!("nb multc:  {:>11}", self.monitor_mulc);
        info!("nb multni: {:>11}", self.monitor_mul_ni);
        info!("nb mult:   {:>11}", self.monitor_mul);
        info!("nb czero:  {:>11}", self.monitor_check_zero);
    }
}

// The prover/verifier structures and functions are generic over a `FiniteField` named `FE`.
// `FE` is the type for the authenticated values whereas the clear values are from
// the underlying prime field `FE::PrimeField`.
type FieldClear<FE> = <FE as FiniteField>::PrimeField;

/// Prover for Diet Mac'n'Cheese.
pub struct DietMacAndCheeseProver<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> {
    is_ok: bool,
    prover: FComProver<FE>,
    channel: C,
    rng: RNG,

    // vector of multiplication triples (x,y,z) satisfying x*y = z.
    mult_check_list: Vec<(MacProver<FE>, MacProver<FE>, MacProver<FE>)>,
    check_zero_list: Vec<MacProver<FE>>,
    monitor: Monitor,
}

/// Type of values produced by and consumed by the Prover.
#[derive(Clone, PartialEq, Debug)]
pub enum ValueProver<FE: FiniteField> {
    Public(FE::PrimeField),
    Private(MacProver<FE>),
}

impl<FE: FiniteField> Default for ValueProver<FE> {
    fn default() -> Self {
        ValueProver::Public(FE::PrimeField::ZERO)
    }
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> DietMacAndCheeseProver<FE, C, RNG> {
    /// Initialize the prover by providing a channel, a random generator and a pair of LPN parameters as defined by svole.
    pub fn init(
        channel: &mut C,
        mut rng: RNG,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            is_ok: true,
            prover: FComProver::init(channel, &mut rng, lpn_setup, lpn_extend)?,
            channel: channel.clone(),
            rng,
            mult_check_list: Vec::with_capacity(QUEUE_CAPACITY),
            check_zero_list: Vec::new(),
            monitor: Monitor::default(),
        })
    }

    // this function should be called before every function exposed publicly by the API.
    fn check_is_ok(&self) -> Result<()> {
        if !self.is_ok {
            return Err(BackendError(
                "An error occurred earlier. This functionality should not be used further".into(),
            ));
        }
        Ok(())
    }

    fn input(&mut self, v: FE::PrimeField) -> Result<MacProver<FE>> {
        let tag = self.prover.input1(&mut self.channel, &mut self.rng, v);
        if tag.is_err() {
            self.is_ok = false;
        }
        Ok(MacProver(v, tag?))
    }

    fn do_mult_check(&mut self) -> Result<()> {
        debug!("do mult_check");
        self.channel.flush()?;
        let r = self.prover.quicksilver_check_multiply(
            &mut self.channel,
            &mut self.rng,
            &self.mult_check_list,
        );
        if r.is_err() {
            self.is_ok = false;
        }
        self.monitor.incr_zk_mult_check(self.mult_check_list.len());
        self.mult_check_list.clear();
        Ok(r?)
    }

    fn push_mult_check_list(
        &mut self,
        e: (MacProver<FE>, MacProver<FE>, MacProver<FE>),
    ) -> Result<()> {
        self.mult_check_list.push(e);

        if self.mult_check_list.len() == QUEUE_CAPACITY {
            self.do_mult_check()?;
        }
        Ok(())
    }

    fn do_check_zero(&mut self) -> Result<()> {
        debug!("do check_zero");
        self.channel.flush()?;
        let r = self
            .prover
            .check_zero(&mut self.channel, &self.check_zero_list);
        if r.is_err() {
            self.is_ok = false;
        }
        self.monitor.incr_zk_check_zero(self.check_zero_list.len());
        self.check_zero_list.clear();
        Ok(r?)
    }

    fn push_check_zero_list(&mut self, e: MacProver<FE>) -> Result<()> {
        self.check_zero_list.push(e);

        if self.check_zero_list.len() == QUEUE_CAPACITY {
            self.do_check_zero()?;
        }
        Ok(())
    }

    /// Assert a value is zero.
    pub fn assert_zero(&mut self, a: &ValueProver<FE>) -> Result<()> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_check_zero();
        match a {
            ValueProver::Public(a1) => {
                if *a1 == FE::PrimeField::ZERO {
                    return Ok(());
                } else {
                    return Err(BackendError("Fail assert_zero".into()));
                }
            }
            ValueProver::Private(a1) => {
                self.push_check_zero_list(*a1)?;
            }
        }
        Ok(())
    }

    /// Add two values.
    pub fn add(&mut self, a: &ValueProver<FE>, b: &ValueProver<FE>) -> Result<ValueProver<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_add();

        match (a, b) {
            (ValueProver::Public(a1), ValueProver::Public(b1)) => {
                self.monitor.incr_monitor_add_ni();
                Ok(ValueProver::Public(*a1 + *b1))
            }
            (ValueProver::Public(a1), ValueProver::Private(b1)) => {
                self.monitor.incr_monitor_add_ni();
                let tag = self.prover.affine_add_cst(*a1, *b1);
                Ok(ValueProver::Private(tag))
            }
            (ValueProver::Private(a1), ValueProver::Public(b1)) => {
                self.monitor.incr_monitor_add_ni();
                let tag = self.prover.affine_add_cst(*b1, *a1);
                Ok(ValueProver::Private(tag))
            }
            (ValueProver::Private(a1), ValueProver::Private(b1)) => {
                Ok(ValueProver::Private(self.prover.add(*a1, *b1)))
            }
        }
    }

    /// Multiply two values.
    pub fn mul(&mut self, a: &ValueProver<FE>, b: &ValueProver<FE>) -> Result<ValueProver<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mul();
        match (a, b) {
            (ValueProver::Public(a1), ValueProver::Public(b1)) => {
                self.monitor.incr_monitor_mul_ni();
                Ok(ValueProver::Public(*a1 * *b1))
            }
            (ValueProver::Public(a1), ValueProver::Private(b1)) => {
                self.monitor.incr_monitor_mul_ni();
                let tag = self.prover.affine_mult_cst(*a1, *b1);
                Ok(ValueProver::Private(tag))
            }
            (ValueProver::Private(a1), ValueProver::Public(b1)) => {
                self.monitor.incr_monitor_mul_ni();
                let tag = self.prover.affine_mult_cst(*b1, *a1);
                Ok(ValueProver::Private(tag))
            }
            (ValueProver::Private(a1), ValueProver::Private(b1)) => {
                let MacProver(a_clr, _a_tag) = a1;
                let MacProver(b_clr, _b_tag) = b1;
                let p = *a_clr * *b_clr;

                let out = self.input(p)?;
                self.push_mult_check_list((*a1, *b1, out))?;
                Ok(ValueProver::Private(out))
            }
        }
    }

    /// Add a value and a constant.
    pub fn addc(&mut self, a: &ValueProver<FE>, b: FE::PrimeField) -> Result<ValueProver<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_addc();
        match a {
            ValueProver::Public(a1) => Ok(ValueProver::Public(*a1 + b)),

            ValueProver::Private(a1) => {
                let tag = self.prover.affine_add_cst(b, *a1);
                Ok(ValueProver::Private(tag))
            }
        }
    }

    /// Multiply a value and a constant.
    pub fn mulc(&mut self, a: &ValueProver<FE>, b: FE::PrimeField) -> Result<ValueProver<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mulc();

        match a {
            ValueProver::Public(a1) => Ok(ValueProver::Public(*a1 * b)),

            ValueProver::Private(a1) => {
                let tag = self.prover.affine_mult_cst(b, *a1);
                Ok(ValueProver::Private(tag))
            }
        }
    }

    /// Input a public value and wraps it in a prover value.
    pub fn input_public(&mut self, val: FieldClear<FE>) -> ValueProver<FE> {
        self.monitor.incr_monitor_instance();
        ValueProver::Public(val)
    }

    /// Input a private value and prover value.
    pub fn input_private(&mut self, v: FieldClear<FE>) -> Result<ValueProver<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_witness();
        let v_tag = self.input(v)?;
        Ok(ValueProver::Private(v_tag))
    }

    /// `finalize` execute its queued multiplication and zero checks.
    /// It can be called at any time and it is also called when the functionality is dropped.
    pub fn finalize(&mut self) -> Result<()> {
        self.check_is_ok()?;
        self.channel.flush()?;
        let zero_len = self.check_zero_list.len();
        self.do_check_zero()?;

        let mult_len = self.mult_check_list.len();
        self.do_mult_check()?;
        debug!(
            "finalize: mult_check:{:?}, check_zero:{:?} ",
            mult_len, zero_len
        );
        self.log_final_monitor();
        Ok(())
    }

    fn log_final_monitor(&self) {
        self.monitor.log_final_monitor();
    }
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> Drop
    for DietMacAndCheeseProver<FE, C, RNG>
{
    fn drop(&mut self) {
        if self.is_ok && (!self.check_zero_list.is_empty() || !self.mult_check_list.is_empty()) {
            warn!("Dropped in unexpected state: either `finalize()` has not been called or an error occured earlier.");
        }
    }
}

/// Type of values produced by and consumed by the Verifier.
#[derive(Clone, PartialEq, Debug)]
pub enum ValueVerifier<FE: FiniteField> {
    Public(FE::PrimeField),
    Private(MacVerifier<FE>),
}

impl<FE: FiniteField> Default for ValueVerifier<FE> {
    fn default() -> Self {
        ValueVerifier::Public(FE::PrimeField::ZERO)
    }
}

/// Verifier for Diet Mac'n'Cheese.
pub struct DietMacAndCheeseVerifier<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> {
    is_ok: bool,
    verifier: FComVerifier<FE>,
    channel: C,
    rng: RNG,

    // vector of multiplication triples (x,y,z) satisfying x*y = z.
    mult_check_list: Vec<(MacVerifier<FE>, MacVerifier<FE>, MacVerifier<FE>)>,
    check_zero_list: Vec<MacVerifier<FE>>,
    monitor: Monitor,
}

impl<'a, FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng>
    DietMacAndCheeseVerifier<FE, C, RNG>
{
    /// Initialize the verifier by providing a channel, a random generator and a pair of LPN parameters as defined by svole.
    pub fn init(
        channel: &mut C,
        mut rng: RNG,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            is_ok: true,
            verifier: FComVerifier::init(channel, &mut rng, lpn_setup, lpn_extend)?,
            channel: channel.clone(),
            rng,
            mult_check_list: Vec::new(),
            check_zero_list: Vec::new(),
            monitor: Monitor::default(),
        })
    }

    // this function should be called before every function exposed publicly by the API.
    fn check_is_ok(&self) -> Result<()> {
        if !self.is_ok {
            return Err(BackendError(
                "An error occurred earlier. This functionality should not be used further".into(),
            ));
        }
        Ok(())
    }

    fn input(&mut self) -> Result<MacVerifier<FE>> {
        let tag = self.verifier.input1(&mut self.channel, &mut self.rng);
        if tag.is_err() {
            self.is_ok = false;
        }
        Ok(tag?)
    }

    fn do_mult_check(&mut self) -> Result<()> {
        debug!("do mult_check");
        self.channel.flush()?;
        let r = self.verifier.quicksilver_check_multiply(
            &mut self.channel,
            &mut self.rng,
            &self.mult_check_list,
        );
        if r.is_err() {
            self.is_ok = false;
        }
        self.monitor.incr_zk_mult_check(self.mult_check_list.len());
        self.mult_check_list.clear();
        Ok(r?)
    }

    fn push_mult_check_list(
        &mut self,
        e: (MacVerifier<FE>, MacVerifier<FE>, MacVerifier<FE>),
    ) -> Result<()> {
        self.mult_check_list.push(e);

        if self.mult_check_list.len() == QUEUE_CAPACITY {
            self.do_mult_check()?;
        }
        Ok(())
    }

    fn do_check_zero(&mut self) -> Result<()> {
        debug!("do check_zero");
        self.channel.flush()?;
        let r = self
            .verifier
            .check_zero(&mut self.channel, &mut self.rng, &self.check_zero_list);
        if r.is_err() {
            self.is_ok = false;
        }
        self.monitor.incr_zk_check_zero(self.check_zero_list.len());
        self.check_zero_list.clear();
        Ok(r?)
    }

    fn push_check_zero_list(&mut self, e: MacVerifier<FE>) -> Result<()> {
        self.check_zero_list.push(e);

        if self.check_zero_list.len() == QUEUE_CAPACITY {
            self.do_check_zero()?;
        }
        Ok(())
    }

    /// Assert a value is zero.
    pub fn assert_zero(&mut self, a: &ValueVerifier<FE>) -> Result<()> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_check_zero();
        match a {
            ValueVerifier::Public(a1) => {
                if *a1 == FE::PrimeField::ZERO {
                    return Ok(());
                } else {
                    return Err(BackendError("Fail assert_zero".into()));
                }
            }
            ValueVerifier::Private(a1) => {
                self.push_check_zero_list(*a1)?;
            }
        }
        Ok(())
    }

    /// Add two values.
    pub fn add(
        &mut self,
        a: &ValueVerifier<FE>,
        b: &ValueVerifier<FE>,
    ) -> Result<ValueVerifier<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_add();

        match (a, b) {
            (ValueVerifier::Public(a1), ValueVerifier::Public(b1)) => {
                self.monitor.incr_monitor_add_ni();
                Ok(ValueVerifier::Public(*a1 + *b1))
            }
            (ValueVerifier::Public(a1), ValueVerifier::Private(b1)) => {
                self.monitor.incr_monitor_add_ni();
                let tag = self.verifier.affine_add_cst(*a1, *b1);
                Ok(ValueVerifier::Private(tag))
            }
            (ValueVerifier::Private(a1), ValueVerifier::Public(b1)) => {
                self.monitor.incr_monitor_add_ni();
                let tag = self.verifier.affine_add_cst(*b1, *a1);
                Ok(ValueVerifier::Private(tag))
            }
            (ValueVerifier::Private(a1), ValueVerifier::Private(b1)) => {
                Ok(ValueVerifier::Private(self.verifier.add(*a1, *b1)))
            }
        }
    }

    /// Multiply two values.
    pub fn mul(
        &mut self,
        a: &ValueVerifier<FE>,
        b: &ValueVerifier<FE>,
    ) -> Result<ValueVerifier<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mul();
        match (a, b) {
            (ValueVerifier::Public(a1), ValueVerifier::Public(b1)) => {
                self.monitor.incr_monitor_mul_ni();
                Ok(ValueVerifier::Public(*a1 * *b1))
            }
            (ValueVerifier::Public(a1), ValueVerifier::Private(b1)) => {
                self.monitor.incr_monitor_mul_ni();
                let tag = self.verifier.affine_mult_cst(*a1, *b1);
                Ok(ValueVerifier::Private(tag))
            }
            (ValueVerifier::Private(a1), ValueVerifier::Public(b1)) => {
                self.monitor.incr_monitor_mul_ni();
                let tag = self.verifier.affine_mult_cst(*b1, *a1);
                Ok(ValueVerifier::Private(tag))
            }
            (ValueVerifier::Private(a1), ValueVerifier::Private(b1)) => {
                let tag = self.input()?;
                self.push_mult_check_list((*a1, *b1, tag))?;
                Ok(ValueVerifier::Private(tag))
            }
        }
    }

    /// Add a value and a constant.
    pub fn addc(&mut self, a: &ValueVerifier<FE>, b: FE::PrimeField) -> Result<ValueVerifier<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_addc();
        match a {
            ValueVerifier::Public(a1) => Ok(ValueVerifier::Public(*a1 + b)),

            ValueVerifier::Private(a1) => {
                let tag = self.verifier.affine_add_cst(b, *a1);
                Ok(ValueVerifier::Private(tag))
            }
        }
    }

    /// Multiply a value and a constant.
    pub fn mulc(&mut self, a: &ValueVerifier<FE>, b: FE::PrimeField) -> Result<ValueVerifier<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_mulc();

        match a {
            ValueVerifier::Public(a1) => Ok(ValueVerifier::Public(*a1 * b)),

            ValueVerifier::Private(a1) => {
                let tag = self.verifier.affine_mult_cst(b, *a1);
                Ok(ValueVerifier::Private(tag))
            }
        }
    }

    /// Input a public value and wraps it in a verifier value.
    pub fn input_public(&mut self, val: FieldClear<FE>) -> ValueVerifier<FE> {
        self.monitor.incr_monitor_instance();
        ValueVerifier::Public(val)
    }

    /// Input a private value and verifier value.
    pub fn input_private(&mut self) -> Result<ValueVerifier<FE>> {
        self.check_is_ok()?;
        self.monitor.incr_monitor_witness();
        let v_tag = self.input()?;
        Ok(ValueVerifier::Private(v_tag))
    }

    /// `finalize` execute its internal queued multiplication and zero checks.
    /// It can be called at any time and it is also be called when the functionality is dropped.
    pub fn finalize(&mut self) -> Result<()> {
        self.check_is_ok()?;
        self.channel.flush()?;
        let zero_len = self.check_zero_list.len();
        self.do_check_zero()?;

        let mult_len = self.mult_check_list.len();
        self.do_mult_check()?;
        debug!(
            "finalize: mult_check:{:?}, check_zero:{:?} ",
            mult_len, zero_len
        );
        self.log_final_monitor();
        Ok(())
    }

    fn log_final_monitor(&self) {
        self.monitor.log_final_monitor();
    }
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> Drop
    for DietMacAndCheeseVerifier<FE, C, RNG>
{
    fn drop(&mut self) {
        if self.is_ok && (!self.check_zero_list.is_empty() || !self.mult_check_list.is_empty()) {
            warn!("Dropped in unexpected state: either `finalize()` has not been called or an error occured earlier.");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::{DietMacAndCheeseProver, DietMacAndCheeseVerifier, ValueProver};
    use ocelot::svole::wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::SeedableRng;
    use scuttlebutt::ring::FiniteRing;
    use scuttlebutt::{
        field::{F61p, FiniteField},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test<FE: FiniteField>() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut dmc: DietMacAndCheeseProver<FE, _, _> =
                DietMacAndCheeseProver::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
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
            let one = FE::PrimeField::ONE;
            let two = one + one;
            let three = two + one;
            let one1 = dmc.input_public(one);
            let one2 = dmc.input_public(one);
            let two_pub = dmc.add(&one1, &one2).unwrap();
            assert_eq!(two_pub, ValueProver::Public(two));
            let three_pub = dmc.addc(&two_pub, FE::PrimeField::ONE).unwrap();
            assert_eq!(three_pub, ValueProver::Public(three));
            let two_priv = dmc
                .input_private(FE::PrimeField::ONE + FE::PrimeField::ONE)
                .unwrap();
            let six = dmc.mul(&two_priv, &three_pub).unwrap();
            let twelve_priv = dmc.mulc(&six, two).unwrap();
            match twelve_priv {
                ValueProver::Public(_) => {
                    panic!("Private value expected")
                }
                ValueProver::Private(x) => {
                    assert_eq!(x.0, three * two * two)
                }
            }
            let n24_priv = dmc.mul(&twelve_priv, &two_priv).unwrap();
            let r_zero_priv = dmc.addc(&n24_priv, -(three * two * two * two)).unwrap();
            dmc.assert_zero(&r_zero_priv).unwrap();
            dmc.finalize().unwrap();
            dmc.assert_zero(&n24_priv).unwrap();
            assert!(dmc.finalize().is_err());
        });

        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut dmc: DietMacAndCheeseVerifier<FE, _, _> =
            DietMacAndCheeseVerifier::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();

        let one = FE::PrimeField::ONE;
        let two = one + one;
        let three = two + one;
        let one1 = dmc.input_public(one);
        let one2 = dmc.input_public(one);
        let two_pub = dmc.add(&one1, &one2).unwrap();
        let three_pub = dmc.addc(&two_pub, FE::PrimeField::ONE).unwrap();
        let two_priv = dmc.input_private().unwrap();
        let six = dmc.mul(&two_priv, &three_pub).unwrap();
        let twelve_priv = dmc.mulc(&six, two).unwrap();
        let n24_priv = dmc.mul(&twelve_priv, &two_priv).unwrap();
        let r_zero_priv = dmc.addc(&n24_priv, -(three * two * two * two)).unwrap();
        dmc.assert_zero(&r_zero_priv).unwrap();
        dmc.finalize().unwrap();
        dmc.assert_zero(&n24_priv).unwrap();
        assert!(dmc.finalize().is_err());

        handle.join().unwrap();
    }

    #[test]
    fn test_f61p() {
        test::<F61p>();
    }
}
