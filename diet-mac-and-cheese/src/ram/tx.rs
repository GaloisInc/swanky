use std::io::Result;

use scuttlebutt::AbstractChannel;
use swanky_field::FiniteField;

/// A Fiat-Shamir channel-wrapper.
#[derive(Clone, Debug)]
pub struct TxChannel<C: AbstractChannel> {
    /// The underlying [`AbstractChannel`].
    pub ch: C,
    /// The Blake3 hasher used to compute digests from bytes read from and
    /// written to `ch`.
    pub tx: blake3::Hasher,
}

impl<C: AbstractChannel> AbstractChannel for TxChannel<C> {
    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        self.ch.read_bytes(buf)?;
        self.tx.update(buf);
        Ok(())
    }

    fn write_bytes(&mut self, buf: &[u8]) -> Result<()> {
        self.tx.update(buf);
        self.ch.write_bytes(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.ch.flush()
    }
}

impl<C: AbstractChannel> TxChannel<C> {
    /// Create a new Fiat-Shamir channel from a channel and Blake3 hasher.
    pub fn new(ch: C, tx: blake3::Hasher) -> Self {
        Self { ch, tx }
    }

    /// Compute a challenge of length `n` from the channel's digest.
    pub fn challenge<F: FiniteField>(&mut self, n: usize) -> Vec<F> {
        let mut out = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            let hsh = self.tx.finalize();
            let a = hsh.as_bytes()[..16].try_into().unwrap();
            out.push(F::from_uniform_bytes(a));
            if i == n - 1 {
                break;
            }
            i += 1;

            let b = hsh.as_bytes()[16..].try_into().unwrap();
            out.push(F::from_uniform_bytes(b));
            i += 1;
        }
        out
    }
}
