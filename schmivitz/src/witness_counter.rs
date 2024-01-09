use eyre::bail;
use mac_n_cheese_sieve_parser::{
    ConversionSemantics, FunctionBodyVisitor, Identifier, Number, RelationVisitor, TypeId,
    TypedWireRange, WireId, WireRange,
};

/// Counter used to traverse a circuit and determine the number of gates that contribute to the
/// extended witness.
///
/// The total extended witness includes two measures:
/// - The number of private inputs (this is the "non-extended" witness)
/// - The number of multiplication gates (this is the "extended" part)
///
/// ## Failure modes
/// This type is only designed to be used with a VOLE-in-the-head circuit. Its methods will fail
/// if it visits a circuit where:
/// - there are gates other than `private-input`, `add`, or `mul`
#[derive(Debug, Default)]
pub(crate) struct ExtendedWitnessCounter {
    /// Count of gates in the circuit whose outputs are part of the extended witness.
    /// TODO: Is this big enough to hold the kinds of circuits we want to handle?
    count: usize,
}

impl ExtendedWitnessCounter {
    pub(crate) fn count(&self) -> usize {
        self.count
    }
}

impl FunctionBodyVisitor for ExtendedWitnessCounter {
    fn new(&mut self, __ty: TypeId, _first: WireId, _last: WireId) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `new` gates");
    }
    fn delete(&mut self, _ty: TypeId, _first: WireId, _last: WireId) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `delete` gates");
    }
    fn add(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: WireId,
    ) -> eyre::Result<()> {
        Ok(())
    }
    fn mul(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: WireId,
    ) -> eyre::Result<()> {
        self.count += 1;
        Ok(())
    }
    fn addc(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &Number,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `addc` gates");
    }
    fn mulc(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &Number,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `mulc` gates");
    }
    fn copy(&mut self, _ty: TypeId, _dst: WireRange, _src: &[WireRange]) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `copy` gates");
    }
    fn constant(&mut self, _ty: TypeId, _dst: WireId, _src: &Number) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `constant` gates");
    }
    fn public_input(&mut self, _ty: TypeId, _dst: WireRange) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `public_input` gates");
    }
    fn private_input(&mut self, _ty: TypeId, _dst: WireRange) -> eyre::Result<()> {
        self.count += 1;
        Ok(())
    }
    fn assert_zero(&mut self, _ty: TypeId, _src: WireId) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `assert_zero` gates");
    }
    fn convert(
        &mut self,
        _dst: TypedWireRange,
        _src: TypedWireRange,
        _semantics: ConversionSemantics,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `convert` gates");
    }
    fn call(
        &mut self,
        _dst: &[WireRange],
        _name: Identifier,
        _args: &[WireRange],
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `call` gates");
    }
}

impl RelationVisitor for ExtendedWitnessCounter {
    type FBV<'a> = Self;
    fn define_function<BodyCb>(
        &mut self,
        _name: Identifier,
        _outputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _inputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _body: BodyCb,
    ) -> eyre::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> eyre::Result<()>,
    {
        bail!("Invalid input: VOLE-in-the-head does not support function definition");
    }

    fn define_plugin_function(
        &mut self,
        _name: Identifier,
        _outputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _inputs: &[mac_n_cheese_sieve_parser::TypedCount],
        _body: mac_n_cheese_sieve_parser::PluginBinding,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support function definition");
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use mac_n_cheese_sieve_parser::text_parser::RelationReader;

    use crate::witness_counter::ExtendedWitnessCounter;

    fn count_circuit(circuit: &str) -> eyre::Result<ExtendedWitnessCounter> {
        let cursor = &mut Cursor::new(circuit.as_bytes());
        let reader = RelationReader::new(cursor)?;
        let mut counter = ExtendedWitnessCounter::default();
        reader.read(&mut counter)?;
        Ok(counter)
    }

    #[test]
    fn private_inputs_count_correctly() -> eyre::Result<()> {
        let private_input_only = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @private(0);
              $2 <- @private(0);
            @end ";
        let counter = count_circuit(private_input_only)?;
        assert_eq!(counter.count(), 3);
        Ok(())
    }

    #[test]
    fn multiplication_gates_count_correctly() -> eyre::Result<()> {
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
            @end ";
        let counter = count_circuit(one_mul)?;
        assert_eq!(counter.count(), 2);

        let many_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @mul(0: $0, $1);
              $3 <- @mul(0: $0, $2);
              $4 <- @mul(0: $0, $3);
              $5 <- @mul(0: $0, $4);
              $6 <- @mul(0: $0, $5);
            @end ";
        let counter = count_circuit(many_mul)?;
        assert_eq!(counter.count(), 7);
        Ok(())
    }

    #[test]
    fn add_gates_are_not_counted_in_extended_witness() -> eyre::Result<()> {
        // These are the same circuits as in `multiplication_gates_count_correctly`, but with an
        // extra `@add` thrown in.
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @add(0: $0, $0);
            @end ";
        let counter = count_circuit(one_mul)?;
        assert_eq!(counter.count(), 2);

        let many_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @mul(0: $0, $1);
              $3 <- @mul(0: $0, $2);
              $7 <- @add(0: $0, $2);
              $4 <- @mul(0: $0, $3);
              $5 <- @mul(0: $0, $4);
              $6 <- @mul(0: $0, $5);
            @end ";
        let counter = count_circuit(many_mul)?;
        assert_eq!(counter.count(), 7);
        Ok(())
    }
}
