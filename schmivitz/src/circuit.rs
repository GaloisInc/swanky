/*! */
use std::path::PathBuf;

use crate::proof::ProverPreparer2;
use diet_mac_and_cheese::{
    circuit_ir::{GateM, TypeStore},
    sieveir_reader_fbs::{read_types, BufRelation, InputFlatbuffers},
};

///
pub struct RelationStreamer {
    rel: BufRelation,
    i: usize,
}

impl RelationStreamer {
    ///
    pub fn new(type_store: &TypeStore, relation: PathBuf) -> Self {
        Self {
            rel: BufRelation::new(&relation, type_store).unwrap(),
            i: 0,
        }
    }
}

impl Iterator for RelationStreamer {
    type Item = GateM;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i < self.rel.gates.len() {
            let g = self.rel.gates[self.i].clone();
            self.i += 1;
            Some(g)
        } else {
            self.i = 0;
            if let Some(_) = self.rel.read_next() {
                self.next()
            } else {
                None
            }
        }
    }
}

///
pub fn run_prover(private_inputs: PathBuf, relation: PathBuf) -> eyre::Result<()> {
    let type_store = read_types(&private_inputs).unwrap();
    let circ = RelationStreamer::new(&type_store, relation);
    let private_inputs = InputFlatbuffers::new_private_inputs(&private_inputs).unwrap();
    let mut prep = ProverPreparer2::new(private_inputs, circ).unwrap();
    prep.compute()?;

    let count = prep.count();

    eyre::Ok(())
}
