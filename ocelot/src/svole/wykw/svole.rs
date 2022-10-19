use super::{
    base_svole::{Receiver as BaseReceiver, Sender as BaseSender},
    spsvole::{SpsReceiver, SpsSender},
    utils::Powers,
};
use crate::svole::wykw::specialization::NoSpecialization;
use crate::{
    errors::Error,
    svole::{SVoleReceiver, SVoleSender},
};
use generic_array::typenum::Unsigned;
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng, SeedableRng,
};
use scuttlebutt::{
    field::FiniteField, ring::FiniteRing, AbstractChannel, AesRng, Block, Malicious, SemiHonest,
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
    params.rows + params.weight + FE::Degree::to_usize()
}

fn lpn_mtx_indices<FE: FiniteField>(
    distribution: &Uniform<u32>,
    mut rng: &mut AesRng,
) -> [(usize, FE::PrimeField); LPN_PARAMS_D] {
    let mut indices = [(0u32, FE::PrimeField::ONE); LPN_PARAMS_D];
    for i in 0..LPN_PARAMS_D {
        let mut rand_idx = distribution.sample(&mut rng);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = distribution.sample(&mut rng);
        }
        indices[i].0 = rand_idx;
        indices[i].1 = FE::PrimeField::random_nonzero(&mut rng);
    }
    indices.map(|(x, y)| (x.try_into().unwrap(), y))
}

/// Subfield VOLE sender.
pub struct Sender<FE: FiniteField> {
    lpn_setup: LpnParams,
    lpn_extend: LpnParams,
    spsvole: SpsSender<FE>,
    base_voles: Vec<(FE::PrimeField, FE)>,
    // Shared RNG with the receiver for generating the LPN matrix.
    lpn_rng: AesRng,
}

impl<FE: FiniteField> Sender<FE> {
    fn send_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
        output: &mut Vec<(FE::PrimeField, FE)>,
    ) -> Result<(), Error> {
        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;
        let r = FE::Degree::to_usize();
        let m = cols / weight;
        // The number of base VOLEs we need to use.
        let used = rows + weight + r;

        debug_assert!(
            self.base_voles.len() >= used,
            "Not enough base sVOLEs: {} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            r
        );

        let uws = self
            .spsvole
            .send(channel, m, &self.base_voles[rows..rows + weight + r], rng)?;
        debug_assert_eq!(uws.len(), cols);

        let leftover = self.base_voles.len() - used;

        // The VOLEs we'll save for the next iteration.
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        // The VOLEs we'll return to the caller.
        output.clear();
        let out_len = cols - num_saved;
        output.reserve(out_len);
        assert!(rows <= 4_294_967_295); // 2^32 -1
        let distribution = Uniform::<u32>::from(0..rows.try_into().unwrap());
        for (i, (e, c)) in uws.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut self.lpn_rng);
            // Compute `x := u A + e` and `z := w A + c`, where `A` is the LPN matrix.
            let mut x = e;
            let mut z = c;
            x += indices
                .iter()
                .map(|(j, a)| self.base_voles[*j].0 * *a)
                .sum();
            z += indices
                .iter()
                .map(|(j, a)| *a * self.base_voles[*j].1)
                .sum();

            if i < num_saved {
                base_voles.push((x, z));
            } else {
                output.push((x, z));
            }
        }
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert_eq!(self.base_voles.len(), num_saved + leftover);
        debug_assert_eq!(output.len(), cols - num_saved);
        Ok(())
    }
}

impl<FE: FiniteField> SVoleSender for Sender<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = Default::default();
        let mut base_sender = BaseSender::<FE, NoSpecialization>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_sender.send(channel, compute_num_saved::<FE>(lpn_setup), rng)?;
        let spsvole = SpsSender::<FE>::init(channel, pows, rng)?;
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

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        output: &mut Vec<(FE::PrimeField, FE)>,
    ) -> Result<(), Error> {
        self.send_internal(
            channel,
            self.lpn_extend,
            compute_num_saved::<FE>(self.lpn_extend),
            rng,
            output,
        )
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut base_voles = Vec::new();
        self.send_internal(
            channel,
            self.lpn_setup,
            compute_num_saved::<FE>(self.lpn_setup),
            rng,
            &mut base_voles,
        )?;
        // let mut extras = Vec::new();
        // self.send_internal(
        //     channel,
        //     LPN_SETUP_PARAMS,
        //     compute_num_saved::<FE>(LPN_SETUP_PARAMS),
        //     rng,
        //     &mut extras,
        // )?;
        // base_voles.extend(extras.into_iter());

        debug_assert!(base_voles.len() >= compute_num_saved::<FE>(self.lpn_extend));
        debug_assert!(self.base_voles.len() >= compute_num_saved::<FE>(self.lpn_extend));

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

/// Subfield VOLE receiver.
pub struct Receiver<FE: FiniteField> {
    lpn_setup: LpnParams,
    lpn_extend: LpnParams,
    spsvole: SpsReceiver<FE>,
    delta: FE,
    base_voles: Vec<FE>,
    // Shared RNG with the sender for generating the LPN matrix.
    lpn_rng: AesRng,
}

impl<FE: FiniteField> Receiver<FE> {
    fn receive_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
        output: &mut Vec<FE>,
    ) -> Result<(), Error> {
        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;
        let r = FE::Degree::to_usize();
        let m = cols / weight;
        // The number of base VOLEs we need to use.
        let used = rows + weight + r;

        debug_assert!(
            self.base_voles.len() >= used,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            r
        );

        let leftover = self.base_voles.len() - used;

        let vs =
            self.spsvole
                .receive(channel, m, &self.base_voles[rows..rows + weight + r], rng)?;
        debug_assert!(vs.len() == cols);
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        output.clear();
        output.reserve(cols - num_saved);
        assert!(rows <= 4_294_967_295); // 2^32 -1
        let distribution = Uniform::<u32>::from(0..rows.try_into().unwrap());
        for (i, b) in vs.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut self.lpn_rng);
            let mut y = b;

            y += indices
                .iter()
                .map(|(j, a)| *a * self.base_voles[*j])
                .sum();

            if i < num_saved {
                base_voles.push(y);
            } else {
                output.push(y);
            }
        }
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert_eq!(output.len(), cols - num_saved);
        Ok(())
    }
}

impl<FE: FiniteField> SVoleReceiver for Receiver<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = Default::default();
        let mut base_receiver = BaseReceiver::<FE>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_receiver.receive(channel, compute_num_saved::<FE>(lpn_setup), rng)?;
        let delta = base_receiver.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, rng)?;
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
        receiver.receive_internal(channel, lpn_setup, 0, rng, &mut base_voles_setup)?;
        receiver.base_voles = base_voles_setup;
        // let mut base_voles_extend = Vec::new();
        // receiver.receive_internal(channel, LPN_SETUP_PARAMS, 0, rng, &mut base_voles_extend)?;
        // receiver.base_voles = base_voles_extend;
        Ok(receiver)
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        output: &mut Vec<FE>,
    ) -> Result<(), Error> {
        self.receive_internal(
            channel,
            self.lpn_extend,
            compute_num_saved::<FE>(self.lpn_extend),
            rng,
            output,
        )
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut base_voles = Vec::new();
        self.receive_internal(
            channel,
            self.lpn_setup,
            compute_num_saved::<FE>(self.lpn_setup),
            rng,
            &mut base_voles,
        )?;
        // let mut extras = Vec::new();
        // self.receive_internal(
        //     channel,
        //     LPN_SETUP_PARAMS,
        //     compute_num_saved::<FE>(LPN_SETUP_PARAMS),
        //     rng,
        //     &mut extras,
        // )?;
        // base_voles.extend(extras.into_iter());

        debug_assert!(base_voles.len() >= compute_num_saved::<FE>(self.lpn_extend));
        debug_assert!(self.base_voles.len() >= compute_num_saved::<FE>(self.lpn_extend));

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
    use super::{Receiver, SVoleReceiver, SVoleSender, Sender, LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use scuttlebutt::{
        field::{F128b, F40b, F61p, FiniteField as FF},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_lpn_svole_<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole =
                Sender::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
            let mut out = Vec::new();
            vole.send(&mut channel, &mut rng, &mut out).unwrap();
            out
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole =
            Receiver::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut vs = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..uws.len() as usize {
            let right = uws[i].0 * vole.delta() + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    fn test_duplicate_svole_<
        FE: FF,
        Sender: SVoleSender<Msg = FE>,
        Receiver: SVoleReceiver<Msg = FE>,
    >() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole =
                Sender::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
            let mut uws = Vec::new();
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
        let mut vs = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs).unwrap();
        let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
        let mut vs2 = Vec::new();
        vole2.receive(&mut channel, &mut rng, &mut vs2).unwrap();
        let mut vs3 = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs3).unwrap();
        assert_ne!(vs2, vs3);
        vs.extend(vs2);
        vs.extend(vs3);

        let uws = handle.join().unwrap();
        for i in 0..uws.len() as usize {
            let right = uws[i].0 * vole.delta() + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    #[test]
    fn test_lpn_svole_gf128() {
        test_lpn_svole_::<F128b, Sender<F128b>, Receiver<F128b>>();
    }

    #[test]
    fn test_lpn_svole_f61p() {
        test_lpn_svole_::<F61p, Sender<F61p>, Receiver<F61p>>();
    }

    #[test]
    fn test_lpn_svole_f40b() {
        test_lpn_svole_::<F40b, Sender<F40b>, Receiver<F40b>>();
    }

    #[test]
    fn test_duplicate_svole() {
        test_duplicate_svole_::<F61p, Sender<F61p>, Receiver<F61p>>();
    }

    #[test]
    fn test_duplicate_svole_f40b() {
        test_duplicate_svole_::<F40b, Sender<F40b>, Receiver<F40b>>();
    }
}
