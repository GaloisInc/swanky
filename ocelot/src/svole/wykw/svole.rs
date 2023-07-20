use super::{
    base_svole::{Receiver as BaseReceiver, Sender as BaseSender},
    spsvole::{SpsReceiver, SpsSender},
    utils::Powers,
};
use crate::errors::Error;
use generic_array::typenum::Unsigned;
use rand::{
    distributions::{Distribution, Uniform},
    Rng, SeedableRng,
};
use scuttlebutt::{
    field::{Degree, DegreeModulo, FiniteField, IsSubFieldOf},
    ring::FiniteRing,
    AbstractChannel, AesRng, Block, Malicious, SemiHonest,
};

// LPN parameters used in the protocol. We use three stages, two sets of LPN
// parameters for setup, and one set of LPN parameters for the extend phase.
// This differs from what is done in the WYKW paper, but based on personal
// communication with one of the authors, is what is used in the implementation.

/// Type for LPN parameters used internally in the setup phase and the extend phase of the
/// protocol. LPN parameters are provided during the initialization of the protocol so that
/// the extension produces small, medium or large number of values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LpnParams {
    /// Hamming weight `t` of the error vector `e` used in the LPN assumption.
    weight: usize,
    /// Number of columns `n` in the LPN matrix.
    cols: usize,
    /// Number of rows `k` in the LPN matrix.
    rows: usize,
}

// LPN parameters for setup0 phase.
// const LPN_SETUP0_PARAMS: LpnParams = LpnParams {
//     weight: 600,
//     cols: 9_600, // cols / weight = 16
//     rows: 1_220,
// };

/// Extra Small LPN parameters for setup phase.
pub const LPN_SETUP_EXTRASMALL: LpnParams = LpnParams {
    weight: 600,
    cols: 2_400, // cols / weight = 4
    rows: 1_220,
};
/// Extra Small LPN parameters for extend phase.
pub const LPN_EXTEND_EXTRASMALL: LpnParams = LpnParams {
    weight: 600,
    cols: 2_400, // cols / weight = 4
    rows: 1_220,
};

/// Small LPN parameters for setup phase.
pub const LPN_SETUP_SMALL: LpnParams = LpnParams {
    weight: 600,
    cols: 9_600, // cols / weight = 16
    rows: 1_220,
};
/// Small LPN parameters for extend phase.
pub const LPN_EXTEND_SMALL: LpnParams = LpnParams {
    weight: 2_600,
    cols: 166_400, // cols / weight = 64
    rows: 5_060,
};

/// Medium LPN parameters for setup phase.
pub const LPN_SETUP_MEDIUM: LpnParams = LpnParams {
    weight: 2_600,
    cols: 166_400, // cols / weight = 64
    rows: 5_060,
};
/// Medium LPN parameters for extend phase.
pub const LPN_EXTEND_MEDIUM: LpnParams = LpnParams {
    weight: 4_965,
    cols: 10_168_320, // cols / weight = 2_048
    rows: 158_000,
};

/// Large LPN parameters for setup phase.
pub const LPN_SETUP_LARGE: LpnParams = LpnParams {
    rows: 19_870,
    cols: 642_048,
    weight: 2_508,
};
/// Large LPN parameters for extend phase.
pub const LPN_EXTEND_LARGE: LpnParams = LpnParams {
    rows: 589_760,
    cols: 10_805_248,
    weight: 1_319,
};

// Constant `d` representing a `d`-local linear code, meaning that each column
// of the LPN matrix contains exactly `d` non-zero entries.
const LPN_PARAMS_D: usize = 10;

// Computes the number of saved VOLEs we need for specific LPN parameters.
fn compute_num_saved<FE: FiniteField>(params: LpnParams) -> usize {
    params.rows + params.weight + Degree::<FE>::USIZE
}

fn lpn_mtx_indices<FE: FiniteField>(
    distribution: &Uniform<u32>,
    mut rng: &mut AesRng,
) -> [(usize, FE::PrimeField); LPN_PARAMS_D] {
    let mut indices = [0u32; LPN_PARAMS_D];
    for i in 0..LPN_PARAMS_D {
        let mut rand_idx = distribution.sample(&mut rng);
        while indices[0..i].iter().any(|&x| x == rand_idx) {
            rand_idx = distribution.sample(&mut rng);
        }
        indices[i] = rand_idx;
    }
    let mut out_indices = [(0, FE::PrimeField::ONE); LPN_PARAMS_D];
    for i in 0..LPN_PARAMS_D {
        out_indices[i].0 = indices[i].try_into().unwrap();
        out_indices[i].1 = FE::PrimeField::random_nonzero(&mut rng);
    }
    out_indices
}

/// Subfield VOLE sender. `T` denotes the [`FiniteField`] type to use for the VOLE tag.
pub struct Sender<T: FiniteField> {
    lpn_setup: LpnParams,
    lpn_extend: LpnParams,
    spsvole: SpsSender<T>,
    // Base VOLEs use a value type of `T::PrimeField`. Generated VOLEs need
    // not, as long as the value type is a subfield of `T`.
    base_voles: Vec<(T::PrimeField, T)>,
    // Shared RNG with the receiver for generating the LPN matrix.
    lpn_rng: AesRng,
}

impl<T: FiniteField> Sender<T> {
    fn send_internal<C: AbstractChannel, V: IsSubFieldOf<T>>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut AesRng,
        output: &mut Vec<(V, T)>,
    ) -> Result<(), Error>
    where
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;
        let degree = Degree::<T>::USIZE;
        let m = cols / weight;
        // The number of base VOLEs we need to use.
        let used = rows + weight + degree;
        // The number of `T::PrimeField` elements to pack in a single `V`
        // element.
        let npacked = DegreeModulo::<T::PrimeField, V>::USIZE;
        // TODO: Can we avoid computing this each time we run `send_internal`?
        let powers = Powers::<V>::default();

        debug_assert!(
            self.base_voles.len() >= used,
            "Not enough base sVOLEs: {} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            degree
        );

        let uws: Vec<(T::PrimeField, T)> = self.spsvole.send(
            channel,
            m,
            &self.base_voles[rows..rows + weight + degree],
            rng,
        )?;
        debug_assert_eq!(uws.len(), cols);

        let leftover = self.base_voles.len() - used;

        // The VOLEs we'll save for the next iteration.
        let mut base_voles: Vec<(T::PrimeField, T)> = Vec::with_capacity(num_saved + leftover);
        // The VOLEs we'll return to the caller.
        output.clear();
        let out_len = cols - num_saved;
        output.reserve(out_len);
        assert!(rows <= 4_294_967_295); // 2^32 -1
        let distribution = Uniform::<u32>::from(0..rows.try_into().unwrap());

        let mut j = 0;
        let mut value = V::ZERO;
        let mut key = T::ZERO;
        for (i, (e, c)) in uws.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<T>(&distribution, &mut self.lpn_rng);
            // Compute `x := u A + e` and `z := w A + c`, where `A` is the LPN matrix.
            let mut x = e;
            let mut z = c;
            for (j, a) in indices.iter() {
                x += self.base_voles[*j].0 * *a;
                z += *a * self.base_voles[*j].1;
            }

            if i < num_saved {
                base_voles.push((x, z));
            } else {
                // We construct the `value` and `key` elements by computing `e_0
                // + e_1 * g + e_2 * g^2 + ...`, where `g` is the field generator.
                value += x.into() * powers.get()[j];
                key += z * self.spsvole.pows.get()[j];
                j += 1;
                if j == npacked {
                    output.push((value, key));
                    // Reset the state so we can pack the next element.
                    j = 0;
                    value = V::ZERO;
                    key = T::ZERO;
                }
            }
        }
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert_eq!(self.base_voles.len(), num_saved + leftover);
        debug_assert_eq!(output.len(), (cols - num_saved) / npacked);
        Ok(())
    }

    /// Initialize the VOLE sender.
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        mut rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self, Error> {
        let pows: Powers<T> = Default::default();
        let mut base_sender = BaseSender::<T>::init(channel, pows.clone(), rng)?;
        let base_voles_setup: Vec<(T::PrimeField, T)> = base_sender.send(
            channel,
            compute_num_saved::<T>(lpn_setup),
            &mut AesRng::from_rng(&mut rng).expect("random number generation shouldn't fail"),
        )?;
        let spsvole = SpsSender::<T>::init(channel, pows, rng)?;
        let seed = rng.gen::<Block>();
        let seed = scuttlebutt::cointoss::receive(channel, &[seed])?[0];
        let lpn_rng = AesRng::from_seed(seed);
        let mut sender = Self {
            lpn_setup,
            lpn_extend,
            spsvole,
            base_voles: base_voles_setup,
            lpn_rng,
        };

        let mut base_voles_setup = Vec::new();
        sender.send_internal(channel, sender.lpn_setup, 0, rng, &mut base_voles_setup)?;
        sender.base_voles = base_voles_setup;
        // let mut base_voles_extend = Vec::new();
        // sender.send_internal(channel, LPN_SETUP_PARAMS, 0, rng, &mut base_voles_extend)?;
        // sender.base_voles = base_voles_extend;
        Ok(sender)
    }

    /// Generate VOLEs. `V` denotes the [`FiniteField`] type to use for the VOLE
    /// value.
    pub fn send<C: AbstractChannel, V: IsSubFieldOf<T>>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        output: &mut Vec<(V, T)>,
    ) -> Result<(), Error>
    where
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        self.send_internal(
            channel,
            self.lpn_extend,
            compute_num_saved::<T>(self.lpn_extend),
            rng,
            output,
        )
    }

    /// Duplicate the sender's state.
    pub fn duplicate<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<Self, Error> {
        let mut base_voles: Vec<(T::PrimeField, T)> = Vec::new();
        self.send_internal(
            channel,
            self.lpn_setup,
            compute_num_saved::<T>(self.lpn_setup),
            rng,
            &mut base_voles,
        )?;

        debug_assert!(base_voles.len() >= compute_num_saved::<T>(self.lpn_extend));
        debug_assert!(self.base_voles.len() >= compute_num_saved::<T>(self.lpn_extend));

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        let lpn_rng = self.lpn_rng.fork();
        Ok(Self {
            lpn_setup: self.lpn_setup,
            lpn_extend: self.lpn_extend,
            spsvole,
            base_voles,
            lpn_rng,
        })
    }
}

/// Subfield VOLE receiver. `T` denotes the [`FiniteField`] type to use for the VOLE tag.
pub struct Receiver<T: FiniteField> {
    lpn_setup: LpnParams,
    lpn_extend: LpnParams,
    spsvole: SpsReceiver<T>,
    delta: T,
    base_voles: Vec<T>,
    // Shared RNG with the sender for generating the LPN matrix.
    lpn_rng: AesRng,
}

impl<T: FiniteField> Receiver<T> {
    fn receive_internal<C: AbstractChannel, V: IsSubFieldOf<T>>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut AesRng,
        output: &mut Vec<T>,
    ) -> Result<(), Error>
    where
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;
        let degree = Degree::<T>::USIZE;
        let m = cols / weight;
        // The number of base VOLEs we need to use.
        let used = rows + weight + degree;
        // The number of elements to pack.
        let npacked = DegreeModulo::<T::PrimeField, V>::USIZE;

        debug_assert!(
            self.base_voles.len() >= used,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            degree
        );

        let leftover = self.base_voles.len() - used;

        let vs = self.spsvole.receive(
            channel,
            m,
            &self.base_voles[rows..rows + weight + degree],
            rng,
        )?;
        debug_assert!(vs.len() == cols);
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        output.clear();
        output.reserve(cols - num_saved);
        assert!(rows <= 4_294_967_295); // 2^32 -1
        let distribution = Uniform::<u32>::from(0..rows.try_into().unwrap());

        let mut j = 0;
        let mut key = T::ZERO;
        for (i, b) in vs.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<T>(&distribution, &mut self.lpn_rng);
            let mut y = b;

            y += indices.iter().map(|(j, a)| *a * self.base_voles[*j]).sum();

            if i < num_saved {
                base_voles.push(y);
            } else {
                // We construct the `key` element  by computing `e_0
                // + e_1 * g + e_2 * g^2 + ...`, where `g` is the field
                //   generator.
                key += y * self.spsvole.pows.get()[j];
                j += 1;
                if j == npacked {
                    output.push(key);
                    // Reset the state so we can pack the next element.
                    j = 0;
                    key = T::ZERO;
                }
            }
        }
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert_eq!(output.len(), (cols - num_saved) / npacked);
        Ok(())
    }

    /// Initialize the VOLE receiver.
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self, Error> {
        let pows: Powers<T> = Default::default();
        let mut base_receiver = BaseReceiver::<T>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_receiver.receive(channel, compute_num_saved::<T>(lpn_setup), rng)?;
        let delta = base_receiver.delta();
        let spsvole = SpsReceiver::<T>::init(channel, pows, delta, rng)?;
        let seed = rng.gen::<Block>();
        let seed = scuttlebutt::cointoss::send(channel, &[seed])?[0];
        let lpn_rng = AesRng::from_seed(seed);
        let mut receiver = Self {
            lpn_setup,
            lpn_extend,
            spsvole,
            delta,
            base_voles: base_voles_setup,
            lpn_rng,
        };
        let mut base_voles_setup = Vec::new();
        receiver.receive_internal::<_, T::PrimeField>(
            channel,
            lpn_setup,
            0,
            rng,
            &mut base_voles_setup,
        )?;
        receiver.base_voles = base_voles_setup;
        Ok(receiver)
    }

    /// Returns the $`Δ`$ value associated with the VOLEs.
    pub fn delta(&self) -> T {
        self.delta
    }

    /// Generate VOLEs. `V` denotes the [`FiniteField`] type to use for the VOLE
    /// value.
    pub fn receive<C: AbstractChannel, V: IsSubFieldOf<T>>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        output: &mut Vec<T>,
    ) -> Result<(), Error>
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        self.receive_internal::<_, V>(
            channel,
            self.lpn_extend,
            compute_num_saved::<T>(self.lpn_extend),
            rng,
            output,
        )
    }

    /// Duplicate the receiver's state.
    pub fn duplicate<C: AbstractChannel, SFE: IsSubFieldOf<T>>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<Self, Error>
    where
        T::PrimeField: IsSubFieldOf<SFE>,
    {
        let mut base_voles = Vec::new();
        self.receive_internal::<_, T::PrimeField>(
            channel,
            self.lpn_setup,
            compute_num_saved::<T>(self.lpn_setup),
            rng,
            &mut base_voles,
        )?;

        debug_assert!(base_voles.len() >= compute_num_saved::<T>(self.lpn_extend));
        debug_assert!(self.base_voles.len() >= compute_num_saved::<T>(self.lpn_extend));

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        let lpn_rng = self.lpn_rng.fork();
        Ok(Self {
            lpn_setup: self.lpn_setup,
            lpn_extend: self.lpn_extend,
            spsvole,
            delta: self.delta,
            base_voles,
            lpn_rng,
        })
    }
}

impl<FF: FiniteField> SemiHonest for Sender<FF> {}
impl<FF: FiniteField> SemiHonest for Receiver<FF> {}
impl<FF: FiniteField> Malicious for Sender<FF> {}
impl<FF: FiniteField> Malicious for Receiver<FF> {}

#[cfg(test)]
mod tests {
    use super::{Receiver, Sender, LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use scuttlebutt::{
        field::{F128b, F40b, F61p, FiniteField, IsSubFieldOf, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_lpn_svole_<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole =
                Sender::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
            let mut out: Vec<(V, T)> = Vec::new();
            vole.send(&mut channel, &mut rng, &mut out).unwrap();
            out
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole =
            Receiver::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut vs: Vec<T> = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..uws.len() as usize {
            assert_eq!(uws[i].1, uws[i].0 * vole.delta() + vs[i]);
            assert_ne!(uws[i].1, T::ZERO);
        }
    }

    fn test_duplicate_svole_<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole =
                Sender::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
            let mut uws: Vec<(V, T)> = Vec::new();
            vole.send(&mut channel, &mut rng, &mut uws).unwrap();
            let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
            let mut uws2 = Vec::new();
            vole2.send(&mut channel, &mut rng, &mut uws2).unwrap();
            let mut uws3 = Vec::new();
            vole.send(&mut channel, &mut rng, &mut uws3).unwrap();
            assert_ne!(uws2, uws3);
            uws.extend(uws2);
            uws.extend(uws3);
            uws
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole =
            Receiver::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut vs: Vec<T> = Vec::new();
        vole.receive::<_, V>(&mut channel, &mut rng, &mut vs)
            .unwrap();
        let mut vole2 = vole.duplicate::<_, V>(&mut channel, &mut rng).unwrap();
        let mut vs2 = Vec::new();
        vole2
            .receive::<_, V>(&mut channel, &mut rng, &mut vs2)
            .unwrap();
        let mut vs3 = Vec::new();
        vole.receive::<_, V>(&mut channel, &mut rng, &mut vs3)
            .unwrap();
        assert_ne!(vs2, vs3);
        vs.extend(vs2);
        vs.extend(vs3);

        let uws = handle.join().unwrap();
        for i in 0..uws.len() as usize {
            assert_eq!(uws[i].1, uws[i].0 * vole.delta() + vs[i]);
        }
    }

    #[test]
    fn test_lpn_svole_f2_f128b() {
        test_lpn_svole_::<F2, F128b>();
    }

    #[test]
    fn test_lpn_svole_f128b_f128b() {
        test_lpn_svole_::<F128b, F128b>();
    }

    #[test]
    fn test_lpn_svole_f61p() {
        test_lpn_svole_::<F61p, F61p>();
    }

    #[test]
    fn test_lpn_svole_f2_f40b() {
        test_lpn_svole_::<F2, F40b>();
    }

    #[test]
    fn test_lpn_svole_f40b_f40b() {
        test_lpn_svole_::<F40b, F40b>();
    }

    #[test]
    fn test_duplicate_svole() {
        test_duplicate_svole_::<F61p, F61p>();
    }

    #[test]
    fn test_duplicate_svole_f2_f40b() {
        test_duplicate_svole_::<F2, F40b>();
    }

    #[test]
    fn test_duplicate_svole_f40b_f40b() {
        test_duplicate_svole_::<F40b, F40b>();
    }
}
