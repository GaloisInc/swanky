use fancy_garbling::circuit::CircuitBuilder;
use fancy_garbling::Fancy;
use fancy_garbling::{circuit::Circuit, circuit::Gate, classic::garble};
use std::convert::TryFrom;
use std::time::SystemTime;

// deps/protos/generated/ DOES NOT work b/c it only contains "APIs" and we want circuits/skcd.proto etc
//
// https://github.com/neoeinstein/protoc-gen-prost/issues/26
#[allow(clippy::derive_partial_eq_without_eq)]
mod interstellarpbskcd {
    include!(concat!(env!("OUT_DIR"), "/interstellarpbskcd.rs"));
}

/// All the Gates type possible in SKCD file format
///
/// SHOULD match
/// - "enum SkcdGateType" from skcd.proto
/// - lib_circuits/src/blif/gate_types.h
/// - lib_garble/src/justgarble/gate_types.h
enum SkcdGateType {
    ZERO = 0,
    NOR = 1,
    /// A-and-not-B
    AANB = 2,
    /// NOT B
    INVB = 3,
    /// not-A-and-B?
    NAAB = 4,
    /// NOT A
    INV = 5,
    XOR = 6,
    NAND = 7,
    AND = 8,
    XNOR = 9,
    BUF = 11,
    /// A-or-NOT-B?
    AONB = 12,
    BUFB = 13,
    /// NOT-A-or-B?
    NAOB = 14,
    OR = 15,
    ONE = 16,
}

impl TryFrom<i32> for SkcdGateType {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            x if x == SkcdGateType::ZERO as i32 => Ok(SkcdGateType::ZERO),
            x if x == SkcdGateType::NOR as i32 => Ok(SkcdGateType::NOR),
            x if x == SkcdGateType::AANB as i32 => Ok(SkcdGateType::AANB),
            x if x == SkcdGateType::INVB as i32 => Ok(SkcdGateType::INVB),
            x if x == SkcdGateType::NAAB as i32 => Ok(SkcdGateType::NAAB),
            x if x == SkcdGateType::INV as i32 => Ok(SkcdGateType::INV),
            x if x == SkcdGateType::XOR as i32 => Ok(SkcdGateType::XOR),
            x if x == SkcdGateType::NAND as i32 => Ok(SkcdGateType::NAND),
            x if x == SkcdGateType::AND as i32 => Ok(SkcdGateType::AND),
            x if x == SkcdGateType::XNOR as i32 => Ok(SkcdGateType::XNOR),
            x if x == SkcdGateType::BUF as i32 => Ok(SkcdGateType::BUF),
            x if x == SkcdGateType::AONB as i32 => Ok(SkcdGateType::AONB),
            x if x == SkcdGateType::BUFB as i32 => Ok(SkcdGateType::BUFB),
            x if x == SkcdGateType::NAOB as i32 => Ok(SkcdGateType::NAOB),
            x if x == SkcdGateType::OR as i32 => Ok(SkcdGateType::OR),
            x if x == SkcdGateType::ONE as i32 => Ok(SkcdGateType::ONE),
            _ => Err(()),
        }
    }
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

/// Additional method "parse_skcd" to fancy_garbling::circuit::Circuit
/// We need a Trait b/c without it we only have access to CircuitBuilder and that
/// is NOT enough; we MUST do like "pub fn parse" and that requires access to "circ.gates"
/// which is not public in CircuitBuilder...
pub trait HasParseSkcd<T> {
    /// Parse a Protobuf-serialized .skcd file
    /// It is doing what fancy-garbling/src/parser.rs is doing for a "Blif Fashion" txt file,
    /// but for a .skcd instead.
    /// SKCD is essentially the same format, but with the gates written in a different order:
    /// - in "Bilf Fashion": gates are written "gate0_input0 gate0_input1 gate0_output gate0_type" etc
    /// - in SKCD: "gate0_input0 gate1_input0 gate2_input0" etc
    fn parse_skcd(buf: &[u8]) -> Result<T, CircuitParserError>;
}

impl HasParseSkcd<Circuit> for Circuit {
    fn parse_skcd(buf: &[u8]) -> Result<Circuit, CircuitParserError> {
        use fancy_garbling::circuit::CircuitRef;
        use std::convert::TryInto;

        let mut buf = &*buf;
        // TODO(interstellar) decode_length_delimited ?
        let skcd: interstellarpbskcd::Skcd = prost::Message::decode(&mut buf).unwrap();
        assert!(
            skcd.a.len() == skcd.b.len()
                && skcd.b.len() == skcd.go.len()
                && skcd.go.len() == skcd.gt.len()
                && skcd.gt.len() == skcd.q.try_into().unwrap(),
            "number of gates inputs/outputs/types DO NOT match!"
        );
        println!("skcd : a = {}", skcd.a.len());

        // let mut circ = Circuit::new(Some(skcd.q.try_into().unwrap()));
        let mut circ_builder = CircuitBuilder::new();

        // TODO(interstellar) modulus: what should we use??
        let q = 2;

        // create a vec of [2,2,2..] containing skcd.n elements
        // that is needed for "evaluator_inputs"
        let mods = vec![2u16; skcd.n.try_into().unwrap()];

        // TODO(interstellar) should we use "garbler_inputs" instead?
        let inputs = circ_builder.evaluator_inputs(&mods);
        // for i in 0..skcd.n as usize {
        //     circ.gates.push(Gate::EvaluatorInput { id: i });
        //     circ.evaluator_input_refs
        //         .push(CircuitRef { ix: i, modulus: q });
        // }

        // TODO(interstellar) pre-generate all gates(skcd.q)? other field?

        // TODO(interstellar) cf parser.rs: "Create a constant wire for negations."?
        // circ.gates.push(Gate::Constant { val: 1 });
        // let oneref = CircuitRef {
        //     ix: skcd.n as usize,
        //     modulus: q,
        // };
        // circ.const_refs.push(oneref);

        // TODO(interstellar) how should we use skcd's a/b/go?
        for g in 0..skcd.q as usize {
            let skcd_input0 = *skcd.a.get(g).unwrap() as usize;
            let skcd_input1 = *skcd.b.get(g).unwrap() as usize;
            let skcd_output = *skcd.go.get(g).unwrap() as usize;
            let skcd_gate_type = *skcd.gt.get(g).unwrap();
            // println!("Processing gate: {}", g);

            let xref = CircuitRef {
                ix: skcd_input0,
                modulus: q,
            };
            let yref = CircuitRef {
                ix: skcd_input1,
                modulus: q,
            };

            // cf "pub trait Fancy"(fancy.rs) for how to build eac htype of Gate
            match skcd_gate_type.try_into() {
                Ok(SkcdGateType::ZERO) => {
                    circ_builder.constant(0, q).unwrap();

                    // circ.gates.push(Gate::Constant { val: 0 })
                }
                // "Or uses Demorgan's Rule implemented with multiplication and negation."
                Ok(SkcdGateType::OR) => {
                    // let x = inputs.get(skcd_input0).unwrap();
                    // let y = inputs.get(skcd_input1).unwrap();
                    let z = circ_builder.or(&xref, &yref).unwrap();
                    circ_builder.output(&z).unwrap();
                }
                // "Xor is just addition, with the requirement that `x` and `y` are mod 2."
                Ok(SkcdGateType::XOR) => {
                    // let x = inputs.get(skcd_input0).unwrap();
                    // let y = inputs.get(skcd_input1).unwrap();
                    let z = circ_builder.xor(&xref, &yref).unwrap();
                    circ_builder.output(&z).unwrap();

                    // circ.gates.push(Gate::Add {
                    //     xref,
                    //     yref,
                    //     out: Some(skcd_output),
                    // })
                }
                Ok(SkcdGateType::NAND) => {
                    // let x = inputs.get(skcd_input0).unwrap();
                    // let y = inputs.get(skcd_input1).unwrap();
                    let z = circ_builder.and(&xref, &yref).unwrap();
                    let z = circ_builder.negate(&z).unwrap();
                    circ_builder.output(&z).unwrap();
                }
                _ => todo!(),
            }
        }

        Ok(circ_builder.finish())
    }
}

fn main() {
    ////////////////////////////////////////////////////////////////////////////

    use std::convert::TryInto;
    use std::io::BufReader;
    use std::io::Read;

    let f = std::fs::File::open(
        "../../lib_garble/tests/data/display_message_120x52_2digits.skcd.pb.bin",
    )
    .unwrap();
    let mut reader = BufReader::new(f);

    let mut buffer = Vec::new();
    // read the whole file
    reader.read_to_end(&mut buffer).unwrap();

    let circ = Circuit::parse_skcd(&buffer).unwrap();

    assert!(circ.num_evaluator_inputs() == 24);
    let outputs = circ.eval_plain(&[], &[0; 24]).unwrap();

    // TODO(interstellar) FIX: nb outputs SHOULD be == 120x52 = 6240; but 6341 for now!
    // possibly linked to  println!("output called"); in fancy-garbling/src/circuit.rs ?

    ////////////////////////////////////////////////////////////////////////////

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
        if res != expected_result {
            println!("FAIL!");
        } else {
            println!("OK!");
        }
    }

    // TODO(interstellar) check eval results; or maybe instead in fancy-garbling/examples/semihonest_2pc.rs ?
}
