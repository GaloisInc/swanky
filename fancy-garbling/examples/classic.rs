use fancy_garbling::circuit::CircuitBuilder;
use fancy_garbling::circuit::CircuitRef;
use fancy_garbling::Fancy;
use fancy_garbling::{circuit::Circuit, circuit::Gate, classic::garble};
use std::collections::HashMap;
use std::collections::HashSet;
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
#[derive(Debug)]
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
    BUF = 10,
    /// A-or-NOT-B?
    AONB = 11,
    BUFB = 12,
    /// NOT-A-or-B?
    NAOB = 13,
    OR = 14,
    ONE = 15,
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
pub trait HasParseSkcd<C> {
    /// Parse a Protobuf-serialized .skcd file
    /// It is doing what fancy-garbling/src/parser.rs is doing for a "Blif Fashion" txt file,
    /// but for a .skcd instead.
    /// SKCD is essentially the same format, but with the gates written in a different order:
    /// - in "Bilf Fashion": gates are written "gate0_input0 gate0_input1 gate0_output gate0_type" etc
    /// - in SKCD: "gate0_input0 gate1_input0 gate2_input0" etc
    ///
    /// return:
    /// - the graph corresponding to the .skcd(as-is; gates NOT transformed/optimized/etc)
    /// - the list of inputs (gate ids)
    /// - the list of ouputs (gate ids)
    /// [inputs/outputs are needed to walk the graph, and optimize/rewrite if desired]
    fn parse_skcd(buf: &[u8]) -> Result<C, CircuitParserError>;
}

/// TODO(interstellar)? Intermediate struct, that way wa can "impl Fancy for MyCircuit"
/// which means we simply have to define the basics constant/add/sub/etc
/// and the rest(xor, and, ...) are built onto of them
// struct MyCircuit {
//     circ: Circuit,
// }

// impl Fancy for MyCircuit {
//     type Item: Clone + HasModulus;

//     /// Errors which may be thrown by the users of Fancy.
//     type Error: std::fmt::Debug + std::fmt::Display + std::convert::From<FancyError>;

//     /// Create a constant `x` with modulus `q`.
//     fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error>;

//     /// Add `x` and `y`.
//     fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

//     /// Subtract `x` and `y`.
//     fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

//     /// Multiply `x` times the constant `c`.
//     fn cmul(&mut self, x: &Self::Item, c: u16) -> Result<Self::Item, Self::Error>;

//     /// Multiply `x` and `y`.
//     fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

//     /// Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.
//     ///
//     /// Optional `tt` is useful for hiding the gate from the evaluator.
//     fn proj(
//         &mut self,
//         x: &Self::Item,
//         q: u16,
//         tt: Option<Vec<u16>>,
//     ) -> Result<Self::Item, Self::Error>;

//     /// Process this wire as output. Some `Fancy` implementors dont actually *return*
//     /// output, but they need to be involved in the process, so they can return `None`.
//     fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error>;
// }

#[derive(Debug)]
enum MyFancyError {}

const MODULUS: u16 = 2;

/// Xor is just addition, with the requirement that `x` and `y` are mod 2.
fn fancy_xor(circ: &mut Circuit, x: &CircuitRef, y: &CircuitRef) -> CircuitRef {
    // TODO(interstellar) fancy: output?
    fancy_add(circ, x, y, None)
}

/// fancy.rs: "Negate by xoring `x` with `1`."
fn fancy_negate(circ: &mut Circuit, x: &CircuitRef, oneref: &CircuitRef) -> CircuitRef {
    fancy_xor(circ, x, oneref)
}

fn fancy_add(circ: &mut Circuit, x: &CircuitRef, y: &CircuitRef, out: Option<usize>) -> CircuitRef {
    let gate = Gate::Add {
        xref: *x,
        yref: *y,
        out: out,
    };
    circ.gates.push(gate);

    CircuitRef {
        ix: circ.gates.len(),
        modulus: MODULUS,
    }
}

#[derive(Debug)]
struct MyCircuitGraphNode {
    gate_type: Option<SkcdGateType>,
}

impl HasParseSkcd<Circuit> for Circuit {
    fn parse_skcd(buf: &[u8]) -> Result<Circuit, CircuitParserError> {
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

        let mut circ_builder = CircuitBuilder::new();

        // TODO(interstellar) modulus: what should we use??
        let q = 2;

        // We need to use a CircuitRef for Fancy gates(fn xor/fn and/etc)
        // which means we must convert a .skcd GateID(integer) to its corresponding CircuitRef
        let mut map_skcd_gate_id_to_circuit_ref: HashMap<usize, CircuitRef> = HashMap::new();

        // create a vec of [2,2,2..] containing skcd.n elements
        // that is needed for "evaluator_inputs"
        // let mods = vec![2u16; skcd.n.try_into().unwrap()];

        // TODO(interstellar) should we use "garbler_inputs" instead?
        // let inputs = circ_builder.evaluator_inputs(&mods);
        for i in 0..skcd.n as usize {
            // circ.gates.push(Gate::EvaluatorInput { id: i });
            // circ.evaluator_input_refs
            //     .push(CircuitRef { ix: i, modulus: q });

            map_skcd_gate_id_to_circuit_ref.insert(i, circ_builder.evaluator_input(q));
        }

        // TODO(interstellar)? parser.rs "Process outputs."
        // IMPORTANT: we MUST use skcd.o to set the CORRECT outputs
        // eg for the 2 bits adder.skcd:
        // - skcd.m = 1
        // - skcd.o = [8,11]
        // -> the 2 CORRECT outputs to be set are: [8,11]
        // If we set the bad ones, we get "FancyError::UninitializedValue" in fancy-garbling/src/circuit.rs at "fn eval"
        // eg L161 etc b/c the cache is not properly set
        // TODO(interstellar) parser.rs proper wires?
        for o in skcd.o {
            let z = CircuitRef {
                ix: o as usize,
                modulus: q,
            };
            // TODO put that in "outputs_refs" vec? and use it below?
            circ_builder.output(&z).unwrap();

            // circ.output_refs.push(CircuitRef {
            //     // TODO(interstellar) parser.rs proper wires?
            //     // ix: nwires - n3 + i,
            //     ix: i as usize,
            //     modulus: q,
            // });
        }

        // We MUST rewrite certain Gate, which means some Gates in .skcd will be converted to several in CircuiBuilder
        // eg OR -> NOT+AND+AND+NOT
        // This means we MUST "correct" the GateID in .skcd by a given offset
        let mut gate_offset = 0;
        let mut current_gates = HashSet::new();

        // TODO(interstellar) how should we use skcd's a/b/go?
        for g in 0..skcd.q as usize {
            // TODO(interstellar) gate_offset?
            let skcd_input0 = *skcd.a.get(g).unwrap() as usize;
            let skcd_input1 = *skcd.b.get(g).unwrap() as usize;
            // TODO(interstellar) graph: how to use skcd_output?
            let skcd_output = *skcd.go.get(g).unwrap() as usize;
            let skcd_gate_type = *skcd.gt.get(g).unwrap();
            // println!("Processing gate: {}", g);

            // let xref = CircuitRef {
            //     ix: skcd_input0 + gate_offset,
            //     modulus: q,
            // };
            // let yref = CircuitRef {
            //     ix: skcd_input1 + gate_offset,
            //     modulus: q,
            // };

            let xref = map_skcd_gate_id_to_circuit_ref.get(&skcd_input0).unwrap();
            let yref = map_skcd_gate_id_to_circuit_ref.get(&skcd_input1).unwrap();

            // cf "pub trait Fancy"(fancy.rs) for how to build eac htype of Gate
            match skcd_gate_type.try_into() {
                Ok(SkcdGateType::ZERO) => {
                    if current_gates.insert(circ_builder.constant(0, q).unwrap()) {
                        gate_offset += 1;
                    }

                    // circ_builder.constant(0, q).unwrap();

                    // circ.gates.push(Gate::Constant { val: 0 })
                }
                Ok(SkcdGateType::ONE) => {
                    if current_gates.insert(circ_builder.constant(1, q).unwrap()) {
                        gate_offset += 1;
                    }

                    // circ_builder.constant(0, q).unwrap();

                    // circ.gates.push(Gate::Constant { val: 0 })
                }
                // "Or uses Demorgan's Rule implemented with multiplication and negation."
                Ok(SkcdGateType::OR) => {
                    // let x = inputs.get(skcd_input0).unwrap();
                    // let y = inputs.get(skcd_input1).unwrap();
                    let z = circ_builder.or(&xref, &yref).unwrap();

                    // TODO(interstellar) output? circ_builder.output(&z);
                    map_skcd_gate_id_to_circuit_ref.insert(skcd_output, z);

                    // fn or(&mut self, x: &Self::Item, y: &Self::Item):
                    // let notx = self.negate(x)?;
                    // let noty = self.negate(y)?;
                    // let z = self.and(&notx, &noty)?;
                    // self.negate(&z)
                    //
                    // let notx = fancy_negate(&mut circ, &xref, &oneref);
                    // let noty = fancy_negate(&mut circ, &yref, &oneref);
                    // // "And is just multiplication, with the requirement that `x` and `y` are mod 2."
                    // let z = Gate::Mul {
                    //     xref: notx,
                    //     yref: noty,
                    //     id: id,
                    //     // TODO(interstellar)
                    //     // out: Some(out),
                    //     out: None,
                    // };

                    // let zref = CircuitRef { ix: id, modulus: q };

                    // id += 1;

                    // fancy_negate(&mut circ, &zref, &oneref);
                }
                // "Xor is just addition, with the requirement that `x` and `y` are mod 2."
                Ok(SkcdGateType::XOR) => {
                    // let x = inputs.get(skcd_input0).unwrap();
                    // let y = inputs.get(skcd_input1).unwrap();
                    let z = circ_builder.xor(&xref, &yref).unwrap();

                    // TODO(interstellar) output? circ_builder.output(&z);
                    map_skcd_gate_id_to_circuit_ref.insert(skcd_output, z);

                    // circ.gates.push(Gate::Add {
                    //     xref,
                    //     yref,
                    //     out: Some(skcd_output),
                    // })

                    // fancy_xor(&mut circ, &xref, &yref);
                }
                Ok(SkcdGateType::NAND) => {
                    // let x = inputs.get(skcd_input0).unwrap();
                    // let y = inputs.get(skcd_input1).unwrap();
                    let z = circ_builder.and(&xref, &yref).unwrap();
                    let z = circ_builder.negate(&z).unwrap();

                    // TODO(interstellar) output? circ_builder.output(&z);
                    map_skcd_gate_id_to_circuit_ref.insert(skcd_output, z);

                    // "And is just multiplication, with the requirement that `x` and `y` are mod 2."
                    // let z = Gate::Mul {
                    //     xref: xref,
                    //     yref: yref,
                    //     id: id,
                    //     // TODO(interstellar)
                    //     // out: Some(out),
                    //     out: None,
                    // };

                    // let zref = CircuitRef { ix: id, modulus: q };

                    // id += 1;

                    // fancy_negate(&mut circ, &zref, &oneref);
                }
                _ => todo!(),
            }
        }

        Ok(circ_builder.finish())
    }
}

fn main() {
    ////////////////////////////////////////////////////////////////////////////

    use std::io::BufReader;
    use std::io::Read;

    let f = std::fs::File::open("../../lib_garble/tests/data/adder.skcd.pb.bin").unwrap();
    let mut reader = BufReader::new(f);

    let mut buffer = Vec::new();
    // read the whole file
    reader.read_to_end(&mut buffer).unwrap();

    let circ = Circuit::parse_skcd(&buffer).unwrap();

    // all_inputs/all_expected_outputs: standard full-adder 2 bits truth table(and expected results)
    // input  i_bit1;
    // input  i_bit2;
    // input  i_carry;
    let all_inputs = vec![
        [0, 0, 0],
        [1, 0, 0],
        [0, 1, 0],
        [1, 1, 0],
        [0, 0, 1],
        [1, 0, 1],
        [0, 1, 1],
        [1, 1, 1],
    ];

    // output o_sum;
    // output o_carry;
    let all_expected_outputs = [
        [0, 0],
        [1, 0],
        [1, 0],
        [0, 1],
        [1, 0],
        [0, 1],
        [0, 1],
        [1, 1],
    ];

    assert!(circ.num_evaluator_inputs() == 3);
    for (i, inputs) in all_inputs.iter().enumerate() {
        let outputs = circ.eval_plain(&[], inputs).unwrap();
        if outputs == all_expected_outputs[i] {
            println!("adder OK");
        } else {
            println!("adder FAIL!");
        }
    }

    //////////////////////////////////
    // TODO refactor "adder" as a test; and then add version with "display" and then write .png

    // let path = "eval_outputs.png";
    // let file = File::create(path).unwrap();
    // let ref mut w = BufWriter::new(file);

    // // TODO(interstellar) get from Circuit's "config"
    // let mut encoder = png::Encoder::new(w, 120, 52);
    // encoder.set_color(png::ColorType::Grayscale);
    // encoder.set_depth(png::BitDepth::Eight);

    // let mut writer = encoder.write_header().unwrap();

    // // let data = [255, 0, 0, 255, 0, 0, 0, 255]; // "An array containing a RGBA sequence. First pixel is red and second pixel is black."
    // let data: Vec<u8> = outputs
    //     .iter()
    //     .map(|v| {
    //         let pixel_value: u8 = (*v).try_into().unwrap();
    //         pixel_value * 255
    //     })
    //     .collect();

    // // TODO(interstellar) FIX: nb outputs SHOULD be == 120x52 = 6240; but 6341 for now!
    // // possibly linked to  println!("output called"); in fancy-garbling/src/circuit.rs ?
    // writer.write_image_data(&data).unwrap(); // Save

    //////////////////////////////////

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
