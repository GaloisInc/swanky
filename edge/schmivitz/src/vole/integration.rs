use super::crypto_primitives::CHALL1_LENGTH;
use super::{AsSecretBytes, Chall3, RandomVoleP, RandomVoleV};
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM, VOLE_SIZE_PARAM};
use crate::vole::functionality::{PartialDecommitment, VoleProver, VoleVerifier};
use merlin::Transcript;
use rand::CryptoRng;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field::IsSubFieldOf;
use swanky_field_binary::{F2, F8b, F128b};

// This is a first attempt to connect the VOLE part to the circuit traverser.

impl RandomVoleP for VoleProver {
    type Decommitment = PartialDecommitment;

    type VoleChallenge = [u8; CHALL1_LENGTH];

    fn create<Secret: AsSecretBytes>(
        extended_witness_length: usize,
        transcript: &mut Transcript,
        secret: &Secret,
        _rng: &mut impl CryptoRng,
    ) -> (Self, Self::VoleChallenge) {
        log::info!("NB VOLES {:?}", extended_witness_length);
        let mut statement_sig = [0u8; SECURITY_PARAM];
        transcript.challenge_bytes(b"statement signature", &mut statement_sig);

        let vole = VoleProver::create(&statement_sig, secret, extended_witness_length);
        let chall = vole.chall1;

        // Part of line 13.
        transcript.append_message(b"u_tilda", &vole.u_tilda.as_bytes());
        transcript.append_message(b"h_V", vole.h_v.as_ref());

        (vole, chall)
    }

    fn count(&self) -> usize {
        self.u.len()
    }

    fn extended_witness_length(&self) -> usize {
        self.count() - REPETITION_PARAM * VOLE_SIZE_PARAM
    }

    fn witness_mask(&self) -> &[F2] {
        &self.u[0..self.extended_witness_length()]
    }

    fn aggregate_commitment_values(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        let ell = self.extended_witness_length();
        self.u[ell..ell + REPETITION_PARAM * VOLE_SIZE_PARAM]
            .iter()
            .map(|f2| F128b::from(*f2))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn aggregate_commitment_masks(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        let ell = self.extended_witness_length();
        self.v[ell..ell + REPETITION_PARAM * VOLE_SIZE_PARAM]
            .to_vec()
            .try_into()
            .unwrap()
    }

    fn vole_mask(&self, i: usize) -> Result<F128b> {
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

    fn decommit(self, challenge: &[u8; SECURITY_PARAM / 8]) -> Self::Decommitment {
        self.decommit(challenge)
    }
}

impl RandomVoleV for VoleVerifier {
    type Decommitment = PartialDecommitment;

    fn reconstruct(
        decom: &Self::Decommitment,
        chall3: &Chall3,
        transcript: &mut Transcript,
    ) -> Self {
        let mut statement_sig = [0u8; SECURITY_PARAM];
        transcript.challenge_bytes(b"statement signature", &mut statement_sig);

        let verifier = VoleVerifier::create(&statement_sig, decom, chall3);
        assert_eq!(verifier.q.len(), verifier.l + SECURITY_PARAM);

        transcript.append_message(b"u_tilda", &verifier.u_tilda().as_bytes());
        transcript.append_message(b"h_V", verifier.h_v().as_ref());

        verifier
    }

    fn extended_witness_length(&self) -> usize {
        // by definition, this should be the same as self.q.len() - REPETITION_PARAM * VOLE_SIZE_PARAM
        self.l
    }

    fn verifier_key_array(&self) -> &[F8b; REPETITION_PARAM] {
        self.delta.as_ref()
    }

    fn verifier_key(&self) -> F128b {
        F8b::form_superfield(&self.delta)
    }

    fn witness_voles(&self) -> &[[F8b; REPETITION_PARAM]] {
        let count = self.q.len();
        &self.q[0..count - SECURITY_PARAM]
    }

    fn mask_voles(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        let count = self.q.len();
        self.q[count - SECURITY_PARAM..]
            .iter()
            .map(|qi| F8b::form_superfield(qi.into()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
