use super::crypto_primitives::Chall1;
use super::{AsSecretBytes, Chall3, RandomVoleP, RandomVoleV, lift};
use crate::parameters::{FLambda, Params, RepetitionParam, SecurityParam};
use crate::vole::functionality::{PartialDecommitment, VoleProver, VoleVerifier};
use crate::vole::{MaskLength, SecurityParamBytes};
use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;
use merlin::Transcript;
use rand::CryptoRng;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field_binary::{F2, F8b};

// This is a first attempt to connect the VOLE part to the circuit traverser.

impl<P: Params> RandomVoleP for VoleProver<P> {
    type Params = P;

    type Decommitment = PartialDecommitment<P>;

    type VoleChallenge = Chall1<P>;

    fn create<Secret: AsSecretBytes>(
        extended_witness_length: usize,
        transcript: &mut Transcript,
        secret: &Secret,
        _rng: &mut impl CryptoRng,
    ) -> (Self, Self::VoleChallenge) {
        log::info!("NB VOLES {:?}", extended_witness_length);
        // FIXME(hamlinb): This appears to use `SECURITY_PARAM` *bytes* of entropy, rather than
        // `SECURITY_PARAM` bits. Looks like we're squeezing too much. Clarify this.
        let mut statement_sig: Array<_, SecurityParam<P>> = Default::default();
        transcript.challenge_bytes(b"statement signature", &mut statement_sig);

        let vole = VoleProver::create(&statement_sig, secret, extended_witness_length);
        let chall = vole.chall1.clone();

        // Part of line 13.
        transcript.append_message(b"u_tilda", &vole.u_tilda.as_bytes());
        transcript.append_message(b"h_V", vole.h_v.as_ref());

        (vole, chall)
    }

    fn count(&self) -> usize {
        self.u.len()
    }

    fn extended_witness_length(&self) -> usize {
        self.count() - MaskLength::<P>::USIZE
    }

    fn witness_mask(&self) -> &[F2] {
        &self.u[0..self.extended_witness_length()]
    }

    fn aggregate_commitment_values(&self) -> Array<FLambda<P>, MaskLength<P>> {
        let ell = self.extended_witness_length();
        self.u[ell..ell + MaskLength::<P>::USIZE]
            .iter()
            .map(|f2| P::f2_embed(*f2))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn aggregate_commitment_masks(&self) -> Array<FLambda<P>, MaskLength<P>> {
        let ell = self.extended_witness_length();
        self.v[ell..ell + MaskLength::<P>::USIZE]
            .to_vec()
            .try_into()
            .unwrap()
    }

    fn vole_mask(&self, i: usize) -> Result<FLambda<P>> {
        if i < self.extended_witness_length() {
            Ok(self.v[i])
        } else {
            bail!(
                ErrorKind::OtherError,
                "vole mask index out of range: should be in [0, {}), but got {}",
                self.extended_witness_length(),
                i
            );
        }
    }

    fn decommit(self, challenge: &Array<u8, SecurityParamBytes<P>>) -> Self::Decommitment {
        self.decommit(challenge)
    }
}

impl<P: Params> RandomVoleV for VoleVerifier<P> {
    type Params = P;

    type Decommitment = PartialDecommitment<P>;

    fn reconstruct(
        decom: &Self::Decommitment,
        chall3: &Chall3<P>,
        transcript: &mut Transcript,
    ) -> Self {
        let mut statement_sig: Array<_, SecurityParam<P>> = Default::default();
        transcript.challenge_bytes(b"statement signature", &mut statement_sig);

        let verifier = VoleVerifier::create(&statement_sig, decom, chall3);
        assert_eq!(verifier.q.len(), verifier.l + SecurityParam::<P>::USIZE);

        transcript.append_message(b"u_tilda", &verifier.u_tilda().as_bytes());
        transcript.append_message(b"h_V", verifier.h_v().as_ref());

        verifier
    }

    fn extended_witness_length(&self) -> usize {
        // by definition, this should be the same as self.q.len() - COMMITMENT_COUNT
        self.l
    }

    fn verifier_key_array(&self) -> &Array<F8b, RepetitionParam<P>> {
        &self.delta
    }

    fn verifier_key(&self) -> FLambda<P> {
        lift::<P>(&self.delta)
    }

    fn witness_voles(&self) -> &[Array<F8b, RepetitionParam<P>>] {
        let count = self.q.len();
        &self.q[0..count - SecurityParam::<P>::USIZE]
    }

    fn mask_voles(&self) -> Array<FLambda<P>, MaskLength<P>> {
        let count = self.q.len();
        self.q[count - SecurityParam::<P>::USIZE..]
            .iter()
            .map(lift::<P>)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
