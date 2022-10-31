use fancy_garbling::{circuit::Circuit, circuit::CircuitBuilder, classic::garble};
use std::time::SystemTime;

// TODO(interstellar) use prost-build? or should we keep using pre-generated?
// https://github.com/neoeinstein/protoc-gen-prost/issues/26
#[allow(clippy::derive_partial_eq_without_eq)]
mod interstellarpbapicircuits {
    // include_bytes!(concat!(env!("OUT_DIR")), "/interstellarpbapicircuits.rs");
    // include_bytes!(concat!(env!("OUT_DIR"), "/interstellarpbapicircuits.rs"));
    //
    // prost-build FAIL in enclave/SGX
    // include!(concat!(env!("OUT_DIR"), "/interstellarpbapicircuits.rs"));
    include!("../deps/protos/generated/rust/interstellarpbapicircuits.rs");
}

/// Errors emitted by the circuit parser.
#[derive(Debug)]
pub enum CircuitParserError {
    /// An I/O error occurred.
    IoError(std::io::Error),
    /// A regular expression parsing error occurred.
    RegexError(regex::Error),
    /// An error occurred parsing an integer.
    ParseIntError,
    /// An error occurred parsing a line.
    ParseLineError(String),
    /// An error occurred parsing a gate type.
    ParseGateError(String),
}

/// Parse a Protobuf-serialized .skcd file
/// It is doing what fancy-garbling/src/parser.rs is doing for a "Blif Fashion" txt file,
/// but for a .skcd instead.
/// SKCD is essentially the same format, but with the gates written in a different order:
/// - in "Bilf Fashion": gates are written "gate0_input0 gate0_input1 gate0_output gate0_type" etc
/// - in SKCD: "gate0_input0 gate1_input0 gate2_input0" etc
fn parse_skcd(filename: &str) -> Result<Circuit, CircuitParserError> {
    let circ_builder = CircuitBuilder::new();

    Ok(circ_builder.finish())
}

fn main() {
    let circ = Circuit::parse("circuits/adder_32bit.txt").unwrap();

    let start = SystemTime::now();

    let (encoder, garbled) = garble(&circ).unwrap();

    println!("Total: {} ms", start.elapsed().unwrap().as_millis());

    // TODO(interstellar) ??? maybe: write to file, read file, eval (ie simulate full chain like api+download by app+eval)
    // see also: fancy-garbling/src/garble.rs

    // TODO(interstellar) how to refactor into "1 party computation"; current code is splitted into "garbler inputs" and "evaluator input"

    // IMPORTANT: LSB is on the left!
    for (ev_inputs, expected_result) in [
        (
            // 0
            vec![0; 32],
            // +1 = 1, no reminder
            vec![
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        ),
        (
            // 1
            vec![
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            // +1 = 2, no reminder
            vec![
                0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        ),
        (
            // X
            vec![
                1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                1, 0, 1, 0,
            ],
            // +1 = X+1, no reminder
            vec![
                0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                1, 0, 1, 0, 0,
            ],
        ),
        (
            // int32 max
            vec![1; 32],
            // +1 = full 0s with a reminder!
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1,
            ],
        ),
    ] {
        let evaluator_inputs = &encoder.encode_evaluator_inputs(&ev_inputs);

        // TODO(interstellar) ???
        // 1 (LSB is on the left!)
        let gb_inputs = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let garbler_inputs = &encoder.encode_garbler_inputs(&gb_inputs);

        let res = garbled
            .eval(&circ, garbler_inputs, evaluator_inputs)
            .unwrap();

        println!("ev_inputs      : {:?} ms", ev_inputs);
        println!("res            : {:?} ms", res);
        println!("expected_result: {:?} ms", expected_result);
        // TODO interstellar
        // assert_eq!(res, expected_result);
        if (res != expected_result) {
            println!("FAIL!");
        } else {
            println!("OK!");
        }
    }

    // TODO(interstellar) check eval results; or maybe instead in fancy-garbling/examples/semihonest_2pc.rs ?
}
