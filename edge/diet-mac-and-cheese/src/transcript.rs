use swanky_field::FiniteField;
use swanky_serialization::CanonicalSerialize;

/// A Fiat-Shamir transcript.
#[derive(Debug, Default)]
pub struct Transcript(blake3::Hasher);

impl Transcript {
    /// Create a new, empty [`Transcript`].
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    /// Absorb `value` into the transcript.
    pub fn absorb<T: CanonicalSerialize>(&mut self, value: T) {
        self.0.update(&value.to_bytes());
    }

    /// Derive a single challenge from the transcript.
    ///
    /// Advances the transcript, so repeated calls produce distinct
    /// challenges.
    pub fn challenge<F: FiniteField>(&mut self) -> F {
        let mut buf: [u8; 16] = [0u8; 16];
        self.0.finalize_xof().fill(&mut buf);
        let chl = F::from_uniform_bytes(&buf);
        self.0.update(&[0]);
        chl
    }

    /// Derive `n` challenges from the transcript, without advancing.
    pub fn challenges<F: FiniteField>(&mut self, n: usize) -> Vec<F> {
        let mut out = Vec::with_capacity(n);
        let mut i = 0;

        while i < n {
            let hsh = self.0.finalize();
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
