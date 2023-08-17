use crate::js_channel::ShimChannel;
use diet_mac_and_cheese::backend_multifield::EvaluatorCirc;
use diet_mac_and_cheese::backend_trait::Party;
use diet_mac_and_cheese::circuit_ir::{CircInputs, TypeStore};
use diet_mac_and_cheese::text_reader::number_to_bytes;
use log::info;
use log::Level;
use mac_n_cheese_sieve_parser::text_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_sieve_parser::ValueStreamKind;
use scuttlebutt::{AesRng, TrackChannel};
use std::collections::VecDeque;
use std::io::Cursor;
use std::panic;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn test_web_macandcheese(instance: &[u8], relation: &[u8], witness: &[u8]) -> bool {
    console_log::init_with_level(Level::Debug).unwrap();
    // This sets the panic hook to the browser console
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let rng = AesRng::new();
    let mut channel = TrackChannel::new(ShimChannel::new());
    let mut inputs = CircInputs::default();

    // Loading the instances
    let mut instances = VecDeque::new();
    let mut stream_inp =
        ValueStreamReader::new(ValueStreamKind::Public, Cursor::new(instance)).unwrap();
    while let Some(v) = stream_inp.next().unwrap() {
        instances.push_back(v);
    }
    let field = stream_inp.modulus();
    let type_id = 0;
    inputs.ingest_instances(type_id, instances);
    info!(
        "Loaded type_id:{:?} field:{:?} num public instances:{:?}",
        type_id,
        number_to_bytes(&field),
        inputs.num_instances(type_id)
    );

    alert("*** INSTANCE LOADING: done!");

    // Loading the witnesses
    let mut witnesses = VecDeque::new();
    let mut stream_inp =
        ValueStreamReader::new(ValueStreamKind::Private, Cursor::new(witness)).unwrap();
    while let Some(v) = stream_inp.next().unwrap() {
        witnesses.push_back(v);
    }
    let field = stream_inp.modulus();
    let type_id = 0;
    inputs.ingest_witnesses(type_id, witnesses);
    info!(
        "Loaded type_id:{:?} field:{:?} num private instances:{:?}",
        type_id,
        number_to_bytes(&field),
        inputs.num_witnesses(type_id)
    );
    alert("*** WITNESS LOADING: done!");

    // Loading the relation
    let rel = RelationReader::new(Cursor::new(relation)).unwrap();
    alert("*** RELATION LOADING: done!");

    let no_batching = false;
    let mut evaluator = EvaluatorCirc::new(
        Party::Prover,
        &mut channel,
        rng,
        inputs,
        TypeStore::try_from(rel.header().types.clone()).unwrap(),
        false,
        no_batching,
    )
    .unwrap();
    let lpn_is_small = true;
    let tmp = evaluator.load_backends(&mut channel, lpn_is_small);
    if tmp.is_err() {
        alert("error while loading backends");
        return false;
    }

    let relation_loaded = Cursor::new(relation);
    let r = evaluator.evaluate_relation_text(relation_loaded);
    if r.is_err() {
        alert("error while zk evaluation");
        return false;
    }
    return true;
}
