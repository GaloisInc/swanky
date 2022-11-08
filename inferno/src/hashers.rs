use blake3::{Hash, Hasher, OutputReader};
use scuttlebutt::field::FiniteField;

use crate::secretsharing::LinearSharing;

// A collection of `N` `Hasher`s, one for each of the `N` parties in the MPC.
pub(crate) struct Hashers<const N: usize> {
    hashers: [Hasher; N],
    // This tracks the number of calls to `self.output` to ensure we're not outputting
    // the same hash multiple times.
    count: u64,
}

impl<const N: usize> Hashers<N> {
    pub fn new() -> Self {
        assert!(N.is_power_of_two());
        let hashers = [(); N].map(|_| Hasher::new());
        Self { hashers, count: 0 }
    }

    // Construct a hash output from the hash of each party's trace.
    // If `unopened` is `None`, this corresponds to the prover.
    // In this case we simply combine the hashes of each party.
    // If `unopened` is `Some((id, com))`, we combine the hashes of each party
    // _except_ the party corresponding to `id`. In this case, we use that party's
    // `com` value instead.
    fn output(&mut self, unopened: Option<(usize, Hash)>) -> OutputReader {
        let mut hasher = Hasher::new_derive_key(&self.count.to_string());
        let (unopened_id, unopened_hash) = match unopened {
            Some((id, hash)) => (id, *hash.as_bytes()),
            None => (usize::MAX, [0u8; 32]),
        };
        for (id, hasher_) in self.hashers.iter().enumerate() {
            if id == unopened_id {
                hasher.update(&unopened_hash);
            } else {
                hasher.update(hasher_.finalize().as_bytes());
            }
        }
        self.count += 1;
        hasher.finalize_xof()
    }

    /// Extract the ID of the party to _not_ open.
    pub fn extract_unopened_party(&mut self, unopened: Option<(usize, Hash)>, n: usize) -> usize {
        let mut output = self.output(unopened);
        let mut result = [0u8; 1];
        output.fill(&mut result);
        let id: usize = result[0] as usize;
        id % n
    }

    /// Extract a challenge field element.
    pub fn extract_challenge<F: FiniteField>(&mut self, unopened: Option<(usize, Hash)>) -> F {
        let mut output = self.output(unopened);
        let mut result = [0u8; 16];
        output.fill(&mut result);
        F::from_uniform_bytes(&result)
    }

    /// Extract the hash of the trace for the given `id`.
    ///
    /// # Panics
    /// Panics if `id >= N`.
    pub fn hash_of_id(&self, id: usize) -> Hash {
        assert!(id < N);
        self.hashers[id].finalize()
    }

    /// Extract the hashes of the traces of all parties.
    pub fn hashes(&self) -> [Hash; N] {
        self.hashers
            .iter()
            .map(|h| h.finalize())
            .collect::<Vec<Hash>>()
            .try_into()
            .unwrap() // This `unwrap` will never fail
    }

    /// Hash a `LinearSharing` into the existing hash state.
    #[inline]
    pub fn hash_sharing<S: LinearSharing<F, N>, F: FiniteField>(&mut self, share: &S) {
        share.hash(&mut self.hashers)
    }

    /// Hash Round 0 of the protocol into the existing hash state.
    pub fn hash_round0<S: LinearSharing<F, N>, F: FiniteField>(&mut self, ws: &[S], zs: &[S]) {
        for w in ws.iter() {
            self.hash_sharing(w);
        }
        for z in zs.iter() {
            self.hash_sharing(z);
        }
    }

    /// Hash Round i (!= 0) of the protocol into the existing hash state.
    pub fn hash_round<S: LinearSharing<F, N>, F: FiniteField>(&mut self, hs: &[S]) {
        for h in hs.iter() {
            h.hash(&mut self.hashers);
        }
    }
}
