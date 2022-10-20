use generic_array::GenericArray;
use scuttlebutt::field::FiniteField;

/// Generates powers of `FE::GENERATOR`.
fn gen_pows<FE: FiniteField>() -> GenericArray<FE, FE::Degree> {
    let mut acc = FE::ONE;
    let mut pows: GenericArray<FE, FE::Degree> = Default::default();
    for item in pows.iter_mut() {
        *item = acc;
        acc *= FE::GENERATOR;
    }
    pows
}

#[derive(Clone)]
pub struct Powers<FE: FiniteField> {
    powers: GenericArray<FE, FE::Degree>,
}

impl<FE: FiniteField> Default for Powers<FE> {
    fn default() -> Self {
        Self {
            powers: super::utils::gen_pows(),
        }
    }
}

impl<FE: FiniteField> Powers<FE> {
    pub fn get(&self) -> &GenericArray<FE, FE::Degree> {
        &self.powers
    }
}
