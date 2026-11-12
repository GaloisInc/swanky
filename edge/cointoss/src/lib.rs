#![deny(missing_docs)]
//! A simple multi-party coin-tossing protocol.
//!
//! This can be used to generate uniformly-random bits for use in a multi-party
//! computation.

use rand_core::{Rng, SeedableRng};

use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr, bail};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

/// Coin tossing sender.
#[inline]
pub fn send(channel: &mut Channel, seeds: &[U8x16]) -> Result<Vec<U8x16>> {
    let mut out = Vec::with_capacity(seeds.len());
    for seed in seeds.iter() {
        let mut rng = SwankyRng::from_seed(*seed);
        let mut com = U8x16::default();
        rng.fill_bytes(com.as_mut());
        channel.write(&com)?;
    }
    channel
        .force_flush()
        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel")?;
    for seed in seeds.iter() {
        let seed_ = channel.read::<U8x16>()?;
        out.push(*seed ^ seed_);
    }
    for seed in seeds.iter() {
        channel.write(seed)?;
    }
    channel
        .force_flush()
        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel")?;
    Ok(out)
}

/// Coin tossing receiver.
#[inline]
pub fn receive(channel: &mut Channel, seeds: &[U8x16]) -> Result<Vec<U8x16>> {
    let mut coms = Vec::with_capacity(seeds.len());
    let mut out = Vec::with_capacity(seeds.len());
    for _ in 0..seeds.len() {
        let com = channel.read::<U8x16>()?;
        coms.push(com);
    }
    for seed in seeds.iter() {
        channel.write(seed)?;
    }
    channel
        .force_flush()
        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel")?;
    for (seed, com) in seeds.iter().zip(coms) {
        let seed_ = channel.read::<U8x16>()?;
        let mut rng_ = SwankyRng::from_seed(seed_);
        let mut check = U8x16::default();
        rng_.fill_bytes(check.as_mut());
        if check != com {
            bail!(ErrorKind::OtherError, "Commitment check failed");
        }
        out.push(*seed ^ seed_)
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_channel::local::local_channel_pair;

    #[test]
    fn test() {
        let seed = rand::random::<U8x16>();
        let seed_ = rand::random::<U8x16>();
        let (output, output_) = local_channel_pair(
            |channel| send(channel, &[seed]),
            |channel| receive(channel, &[seed_]),
        )
        .unwrap();

        assert_eq!(output[0], seed ^ seed_);
        assert_eq!(output_[0], seed ^ seed_);
    }
}
