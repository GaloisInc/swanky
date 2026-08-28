/*!
 * Circuit and Memory
 *
 * This module provides a `Circuit` data-structure with functionalities to parse from SIEVE-IR.
 * The evaluation of a circuit requires a memory that is implemented with `CircuitMemory`.
*/
use crate::parameters::FIELD_SIZE;
use diet_mac_and_cheese::fields::SieveIrDeserialize;
use fancy_traits::{
    Circuit as FancyCircuit, FancyBinary, FancyBinaryConstant, FancyEncode, FancyZeroKnowledge,
};
use mac_n_cheese_sieve_parser::{
    ConversionSemantics, FunctionBodyVisitor, Identifier, Number, RelationVisitor, Type, TypeId,
    TypedWireRange, ValueStreamKind, ValueStreamReader as ValueStreamReaderT, WireId, WireRange,
    text_parser::RelationReader, text_parser::ValueStreamReader,
};
use std::{
    cmp::max,
    fs::File,
    io::{Cursor, Read, Seek, Write},
    path::Path,
};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, bail, swanky_error};
use swanky_field::PrimeFiniteField;
use swanky_field_binary::F2;
use swanky_sieve_ir_api::{CircuitExecuter, FieldBackend};
use tempfile::tempdir;

/// Gates
///
/// This is a super set of what voleith is supporting and copied from diet-mac-and-cheese.
/// Note that conversation gates and function call gates are excluded from this list to reduce the amount
/// of data-structure that is not supported in this crate.
#[derive(Clone, Debug)]
pub enum GateM {
    /// Write the value to the given `WireId`.
    Constant(TypeId, WireId, Box<Number>),

    /// Assert that the element on [`WireId`] is zero.
    AssertZero(TypeId, WireId),

    /// Copy ranges of wires.
    Copy(TypeId, WireRange, Box<Vec<WireRange>>),

    /// Add the values on two `WireId`, storing the result.
    Add(TypeId, WireId, WireId, WireId),

    /// Subtract the values on two `WireId`, storing the result.
    Sub(TypeId, WireId, WireId, WireId),

    /// Multiply the values on two `WireId`, storing the result.
    Mul(TypeId, WireId, WireId, WireId),

    /// Add a constant to the value on a `WireId`, storing the result.
    AddConstant(TypeId, WireId, WireId, Box<Number>),

    /// Multiply the value on a `WireId` by a constant, storing the result.
    MulConstant(TypeId, WireId, WireId, Box<Number>),

    /// Get public instances from the scope's queue, storing to the `WireRange`.
    Instance(TypeId, WireRange),

    /// Get private witnesses from the scope's queue, storing to the
    /// `WireRange`.
    Witness(TypeId, WireRange),

    /// Allocate a new, uninitialized range of wires.
    New(TypeId, WireId, WireId),

    /// Delete/free a range of wires.
    Delete(TypeId, WireId, WireId),

    /// Get a random challenge value, storing the result.
    Challenge(TypeId, WireId),

    /// An informational comment.
    Comment(String),
}

fn ingest_private_inputs_from_path(path: &Path) -> swanky_error::Result<Vec<F2>> {
    let mut private_inputs_text = ValueStreamReader::open(ValueStreamKind::Private, path)?;

    let mut private_inputs = vec![];
    while let Some(value) = private_inputs_text.next()? {
        let maybe_f2: Option<F2> = F2::try_from_int(value).into();
        let f2 = maybe_f2.ok_or_else(|| {
            swanky_error!(
                ErrorKind::OtherError,
                "Invalid input: Private input was not in F2"
            )
        })?;

        // Save private input
        private_inputs.push(f2);
    }

    Ok(private_inputs)
}

pub(crate) struct CircuitIngestor {
    gates: Vec<GateM>,
    priv_inputs: Vec<F2>,
    private_input_count: u64,
    is_prover: bool,
    max_wire_id: WireId,
}

impl CircuitIngestor {
    pub(crate) fn new_prover(private_inputs: Vec<F2>) -> swanky_error::Result<Self> {
        Ok(Self {
            gates: vec![],
            priv_inputs: private_inputs,
            private_input_count: 0,
            is_prover: true,
            max_wire_id: 0,
        })
    }

    pub(crate) fn new_verifier() -> swanky_error::Result<Self> {
        Ok(Self {
            gates: vec![],
            priv_inputs: vec![],
            private_input_count: 0,
            is_prover: false,
            max_wire_id: 0,
        })
    }

    fn update_max_output_wire(&mut self, wid: WireId) {
        self.max_wire_id = max(self.max_wire_id, wid);
    }

    pub(crate) fn into_circuit(self) -> Circuit {
        Circuit {
            gates: self.gates,
            private_inputs: self.priv_inputs,
            max_wire_id: self.max_wire_id,
        }
    }
}

impl FunctionBodyVisitor for CircuitIngestor {
    fn new(&mut self, __ty: TypeId, _first: WireId, _last: WireId) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `new` gates"
        );
    }
    fn delete(&mut self, _ty: TypeId, _first: WireId, _last: WireId) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `delete` gates"
        );
    }
    fn add(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()> {
        self.gates.push(GateM::Add(ty, dst, left, right));
        self.update_max_output_wire(dst);
        Ok(())
    }

    fn mul(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()> {
        self.gates.push(GateM::Mul(ty, dst, left, right));
        self.update_max_output_wire(dst);
        Ok(())
    }

    fn addc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()> {
        self.gates
            .push(GateM::AddConstant(ty, dst, left, Box::new(*right)));
        self.update_max_output_wire(dst);
        Ok(())
    }
    fn mulc(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &Number,
    ) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `mulc` gates"
        );
    }
    fn copy(
        &mut self,
        _ty: TypeId,
        _dst: WireRange,
        _src: &[WireRange],
    ) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `copy` gates"
        );
    }
    fn constant(&mut self, _ty: TypeId, _dst: WireId, _src: &Number) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `constant` gates"
        );
    }
    fn public_input(&mut self, _ty: TypeId, _dst: WireRange) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `public_input` gates"
        );
    }

    fn private_input(&mut self, ty: TypeId, dst: WireRange) -> swanky_error::Result<()> {
        if self.is_prover {
            let how_many_wires = dst.end - dst.start + 1;
            if self.private_input_count + how_many_wires > (self.priv_inputs.len() as u64) {
                bail!(
                    ErrorKind::OtherError,
                    "Not enough private inputs for this circuit. The circuit requires more than {} private inputs",
                    self.private_input_count + 1
                );
            }
            self.private_input_count += how_many_wires;
        }

        self.gates.push(GateM::Witness(ty, dst));
        self.update_max_output_wire(dst.end);
        Ok(())
    }

    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> swanky_error::Result<()> {
        self.gates.push(GateM::AssertZero(ty, src));
        Ok(())
    }
    fn convert(
        &mut self,
        _dst: TypedWireRange,
        _src: TypedWireRange,
        _semantics: ConversionSemantics,
    ) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `convert` gates"
        );
    }
    fn call(
        &mut self,
        _dst: &[WireRange],
        _name: Identifier,
        _args: &[WireRange],
    ) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support `call` gates"
        );
    }
}

impl RelationVisitor for CircuitIngestor {
    type FBV<'a> = Self;
    fn define_function<BodyCb>(
        &mut self,
        _name: Identifier,
        _outputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _inputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _body: BodyCb,
    ) -> swanky_error::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> swanky_error::Result<()>,
    {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support function definition"
        );
    }

    fn define_plugin_function(
        &mut self,
        _name: Identifier,
        _outputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _inputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _body: mac_n_cheese_sieve_parser::PluginBinding,
    ) -> swanky_error::Result<()> {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid input: VOLE-in-the-head does not support function definition"
        );
    }
}

/// Circuit
#[derive(Debug, Default, Clone)]
pub struct Circuit {
    /// gates
    pub gates: Vec<GateM>,
    /// private inputs
    pub private_inputs: Vec<F2>,
    /// Max wire id
    pub max_wire_id: WireId,
}

impl Circuit {
    /// Split up a circuit into its interpreter and witness.
    pub fn to_interpreter(&self) -> (CircuitInterpreter<'_>, &[F2], WireId) {
        let interp = CircuitInterpreter {
            gates: &self.gates,
            max_wire_id: self.max_wire_id,
        };
        (interp, &self.private_inputs, self.max_wire_id)
    }
}

/// An interpreter for dynamically parsed circuits.
pub struct CircuitInterpreter<'a> {
    gates: &'a [GateM],
    max_wire_id: u64,
}

// TODO: Remove! This API has been replaced with the `fancy-traits::Circuit`
// API. We're keeping this around for now for backwards compatibility.
impl<'a> CircuitExecuter<F2> for CircuitInterpreter<'a> {
    fn execute<B: FieldBackend<F2>>(&self, backend: &mut B) -> Result<()> {
        let mut memory = CircuitMemory::<B::Wire>::new(self.max_wire_id);
        for g in self.gates.iter() {
            match g {
                GateM::Add(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);
                    let left = memory.get(left);
                    let right = memory.get(right);

                    let res = backend.add(&left, &right)?;

                    memory.insert(*dst, res);
                }
                GateM::Mul(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);
                    let left = memory.get(left);
                    let right = memory.get(right);

                    let res = backend.mul(&left, &right)?;

                    memory.insert(*dst, res);
                }
                GateM::AddConstant(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    let left = memory.get(left);
                    let right = F2::from_number(right)?;
                    let res = backend.addc(&left, right)?;

                    memory.insert(*dst, res);
                }
                GateM::Witness(ty, dst) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    for wid in dst.start..=dst.end {
                        let res = backend.input_private()?;

                        memory.insert(wid, res);
                    }
                }
                GateM::AssertZero(ty, src) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    let src = memory.get(src);
                    backend.assert_zero(&src)?;
                }
                _ => unimplemented!("VOLE-in-the-head does not support gate `{g:?}`"),
            }
        }
        Ok(())
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant + FancyZeroKnowledge + FancyEncode> FancyCircuit<F>
    for CircuitInterpreter<'a>
{
    type Input = ();
    type Output = Vec<F::Item>; // TODO: This should be `()`.

    fn execute(
        &self,
        backend: &mut F,
        _: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut memory = CircuitMemory::<F::Item>::new(self.max_wire_id);
        for g in self.gates.iter() {
            match g {
                GateM::AssertZero(ty, src) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    let src = memory.get(src);
                    backend.assert_zero(&src, channel)?;
                }
                GateM::Add(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    let left = memory.get(left);
                    let right = memory.get(right);

                    let res = backend.xor(&left, &right);

                    memory.insert(*dst, res);
                }
                GateM::Mul(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    let left = memory.get(left);
                    let right = memory.get(right);

                    let res = backend.and(&left, &right, channel)?;

                    memory.insert(*dst, res);
                }
                GateM::AddConstant(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    let left = memory.get(left);
                    let right = F2::from_number(right)?;
                    let right = backend.constant(right);

                    let res = backend.xor(&left, &right);

                    memory.insert(*dst, res);
                }
                GateM::Witness(ty, dst) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(*ty, 0);

                    for wid in dst.start..=dst.end {
                        let res = backend.receive(2, channel)?;

                        memory.insert(wid, res);
                    }
                }
                _ => bail!(
                    ErrorKind::OtherError,
                    "Invalid input: VOLE-in-the-head does not support gate {g:?}"
                ),
            }
        }
        Ok(vec![])
    }
}

/// Validate that the circuit can be processed by the system, according to the header info.
///
/// Note that the system can still fail to form proofs over circuits that pass this check, like
/// if it includes an unsupported gate.
///
/// Requirements:
/// - Must not allow any plugins
/// - Must not allow any conversions
/// - Must not allow any types other than $`\mathbb F_2`$
fn validate_circuit_header<T: Read + Seek>(
    circuit_reader: &RelationReader<T>,
) -> swanky_error::Result<()> {
    let header = circuit_reader.header();
    if !header.plugins.is_empty() {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid circuit: VOLE-in-the-head does not support any plugins"
        )
    }

    if !header.conversion.is_empty() {
        bail!(
            ErrorKind::UnsupportedError,
            "Invalid circuit: VOLE-in-the-head does not support conversions"
        )
    }

    let expected_modulus = Number::from(FIELD_SIZE as u64);
    match header.types[..] {
        [Type::Field { modulus }] if modulus == expected_modulus => {}
        _ => bail!(
            ErrorKind::UnsupportedError,
            "Invalid circuit: VOLE-in-the-head only supports elements in F_2"
        ),
    }

    Ok(())
}

/// Load a circuit as prover
pub fn load_circuit_prover<T: Read + Seek + Clone>(
    circuit_text: &mut T,
    private_input_path: &Path,
) -> swanky_error::Result<Circuit> {
    let reader = RelationReader::new(circuit_text)?;
    validate_circuit_header(&reader)?;

    let private_inputs = ingest_private_inputs_from_path(private_input_path)?;
    let mut circ = CircuitIngestor::new_prover(private_inputs)?;
    reader.read(&mut circ)?;
    let circ_loaded: Circuit = circ.into_circuit();

    Ok(circ_loaded)
}

/// Load a circuit as verifier
pub fn load_circuit_verifier<T: Read + Seek + Clone>(
    circuit_text: &mut T,
) -> swanky_error::Result<Circuit> {
    let reader = RelationReader::new(circuit_text)?;
    validate_circuit_header(&reader)?;

    let mut circ = CircuitIngestor::new_verifier()?;
    reader.read(&mut circ)?;
    let circ_loaded: Circuit = circ.into_circuit();

    Ok(circ_loaded)
}

/// Load circuit from strings for the relation and the private inputs
pub fn load_circuit_from_strings_prover(
    circuit_bytes: &'static str,
    private_input_bytes: &'static str,
) -> swanky_error::Result<Circuit> {
    let mut circuit_cursor = Cursor::new(circuit_bytes.as_bytes());

    let dir = tempdir().unwrap();
    let private_input_path = dir.path().join("schmivitz_private_inputs");
    let mut private_input = File::create(private_input_path.clone()).unwrap();
    writeln!(private_input, "{}", private_input_bytes).unwrap();

    let circuit = load_circuit_prover(&mut circuit_cursor, &private_input_path)?;

    Ok(circuit)
}

/// Circuit Memory
#[derive(Debug)]
pub(crate) struct CircuitMemory<F> {
    /// NOTE: the use of Vec instead of HashMap/BTreeMap brings a >2x performance increase on benchmarked circuits for AES-256 and SHA256.
    cont: Vec<F>,
}

impl<F: Default + Clone> CircuitMemory<F> {
    /// Create a new circuit memory.
    ///
    /// Provided the maximum wire id, it will prepare a memory ready to received contents for
    /// wires up to this maximum wire id.
    pub(crate) fn new(max_wire_id: WireId) -> Self {
        let size = max_wire_id as usize + 1;
        CircuitMemory {
            cont: vec![F::default(); size],
        }
    }

    /// Insert in the memory at wire id `wid` and value `e`.
    ///
    /// This function assumes that it is called on a memory associated with a well-formed circuit,
    /// more specifically that the wire id has not been previously set, so that it does not have to
    /// return the stored old value.
    pub(crate) fn insert(&mut self, wid: WireId, e: F) {
        let idx: usize = wid as usize;
        self.cont[idx] = e;
    }

    /// Get from the memory the value stored at the memory indexed by wire id `wid`.
    ///
    /// This function assumes that it is called on a memory associated with a well-formed circuit,
    /// more specifically that the wire id has been previously set.
    pub(crate) fn get(&self, wid: &WireId) -> F {
        self.cont[*wid as usize].clone()
    }
}

#[cfg(test)]
mod tests {
    use mac_n_cheese_sieve_parser::text_parser::RelationReader;
    use std::io::Cursor;

    #[test]
    fn header_cannot_include_plugins() {
        let plugin = "version 2.0.0;
            circuit;
            @type field 2;
            @plugin mux_v0;
            @begin
            @end ";
        let plugin_cursor = &mut Cursor::new(plugin.as_bytes());
        let reader = RelationReader::new(plugin_cursor).unwrap();
        assert!(super::validate_circuit_header(&reader).is_err());
    }

    #[test]
    fn header_cannot_include_conversions() {
        // The conversion is from self->self because adding an extra type is a different failure case
        let trivial_conversion = "version 2.0.0;
            circuit;
            @type field 2;
            @convert(@out: 0:1, @in: 0:1);
            @begin
            @end ";
        let conversion_cursor = &mut Cursor::new(trivial_conversion.as_bytes());
        let reader = RelationReader::new(conversion_cursor).unwrap();
        assert!(super::validate_circuit_header(&reader).is_err());
    }

    #[test]
    fn header_cannot_include_non_boolean_fields() {
        let big_field = "version 2.0.0;
            circuit;
            @type field 2305843009213693951;
            @begin
            @end ";
        let big_field_cursor = &mut Cursor::new(big_field.as_bytes());
        let reader = RelationReader::new(big_field_cursor).unwrap();
        assert!(super::validate_circuit_header(&reader).is_err());

        let extra_field = "version 2.0.0;
            circuit;
            @type field 2;
            @type field 2305843009213693951;
            @begin
            @end ";
        let extra_field_cursor = &mut Cursor::new(extra_field.as_bytes());
        let reader = RelationReader::new(extra_field_cursor).unwrap();
        assert!(super::validate_circuit_header(&reader).is_err());
    }

    #[test]
    fn tiny_header_works() -> swanky_error::Result<()> {
        let tiny_header = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
            @end ";
        let tiny_header_cursor = &mut Cursor::new(tiny_header.as_bytes());
        let reader = RelationReader::new(tiny_header_cursor)?;
        assert!(super::validate_circuit_header(&reader).is_ok());
        Ok(())
    }
}
