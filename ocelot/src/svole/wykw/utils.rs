use scuttlebutt::{
    field::{Degree, FiniteField},
    generic_array_length::Arr,
};

/// Generates powers of `FE::GENERATOR`.
fn gen_pows<FE: FiniteField>() -> Arr<FE, Degree<FE>> {
    let mut acc = FE::ONE;
    let mut pows: Arr<FE, Degree<FE>> = Default::default();
    for item in pows.iter_mut() {
        *item = acc;
        acc *= FE::GENERATOR;
    }
    pows
}

#[derive(Clone)]
pub struct Powers<FE: FiniteField> {
    powers: Arr<FE, Degree<FE>>,
}

impl<FE: FiniteField> Default for Powers<FE> {
    fn default() -> Self {
        Self {
            powers: super::utils::gen_pows(),
        }
    }
}

impl<FE: FiniteField> Powers<FE> {
    pub fn get(&self) -> &Arr<FE, Degree<FE>> {
        &self.powers
    }
}
