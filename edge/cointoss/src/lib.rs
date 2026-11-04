#![deny(missing_docs)]
//! A simple multi-party coin-tossing protocol.
//!
//! This can be used to generate uniformly-random bits for use in a multi-party
//! computation.

use rand_core::{Rng, SeedableRng};

use swanky_channel_legacy::AbstractChannel;
use swanky_error::{ErrorKind, Result, WrapErr, bail};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

/// Coin tossing sender.
#[inline]
pub fn send<C: AbstractChannel>(channel: &mut C, seeds: &[U8x16]) -> Result<Vec<U8x16>> {
    let mut out = Vec::with_capacity(seeds.len());
    for seed in seeds.iter() {
        let mut rng = SwankyRng::from_seed(*seed);
        let mut com = U8x16::default();
        rng.fill_bytes(com.as_mut());
        channel
            .write_u8x16(&com)
            .wrap_err(ErrorKind::NetworkError, "Failed to write block")?;
    }
    channel
        .flush()
        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel")?;
    for seed in seeds.iter() {
        let seed_ = channel
            .read_u8x16()
            .wrap_err(ErrorKind::NetworkError, "Failed to read block")?;
        out.push(*seed ^ seed_);
    }
    for seed in seeds.iter() {
        channel
            .write_u8x16(seed)
            .wrap_err(ErrorKind::NetworkError, "Failed to write block")?;
    }
    channel
        .flush()
        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel")?;
    Ok(out)
}

/// Coin tossing receiver.
#[inline]
pub fn receive<C: AbstractChannel>(channel: &mut C, seeds: &[U8x16]) -> Result<Vec<U8x16>> {
    let mut coms = Vec::with_capacity(seeds.len());
    let mut out = Vec::with_capacity(seeds.len());
    for _ in 0..seeds.len() {
        let com = channel
            .read_u8x16()
            .wrap_err(ErrorKind::NetworkError, "Failed to read block")?;
        coms.push(com);
    }
    for seed in seeds.iter() {
        channel
            .write_u8x16(seed)
            .wrap_err(ErrorKind::NetworkError, "Failed to write block")?;
    }
    channel
        .flush()
        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel")?;
    for (seed, com) in seeds.iter().zip(coms) {
        let seed_ = channel
            .read_u8x16()
            .wrap_err(ErrorKind::NetworkError, "Failed to read block")?;
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
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    use swanky_channel_legacy::Channel;

    #[test]
    fn test() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<U8x16>();
        let seed_ = rand::random::<U8x16>();
        let handle = std::thread::spawn(move || {
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let output = send(&mut channel, &[seed]).unwrap();
            assert_eq!(output[0], seed ^ seed_);
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let output_ = receive(&mut channel, &[seed_]).unwrap();
        assert_eq!(output_[0], seed ^ seed_);
        handle.join().unwrap();
    }
}
