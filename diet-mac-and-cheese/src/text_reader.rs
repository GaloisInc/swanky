//! SIEVE IR0+ text reader.

use crate::circuit_ir::{FunStore, FuncDecl, GateM, TypeStore};
use log::info;
use mac_n_cheese_sieve_parser::{
    FunctionBodyVisitor, Identifier, Number, PluginBinding, RelationVisitor, TypeId, TypedCount,
    TypedWireRange, WireId, WireRange,
};

#[derive(Default)]
pub(crate) struct TextRelation {
    pub(crate) type_store: TypeStore,
    pub(crate) fun_store: FunStore,
    pub(crate) gates: Vec<GateM>,
}

impl TextRelation {
    pub(crate) fn new(type_store: TypeStore, fun_store: FunStore) -> Self {
        Self {
            type_store,
            fun_store,
            gates: Default::default(),
        }
    }
}

impl FunctionBodyVisitor for TextRelation {
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::New(ty, first, last));
        Ok(())
    }
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::Delete(ty, first, last));
        Ok(())
    }
    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::Add(ty, dst, left, right));
        Ok(())
    }
    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::Mul(ty, dst, left, right));
        Ok(())
    }
    fn addc(&mut self, ty: TypeId, dst: WireId, left: WireId, &right: &Number) -> eyre::Result<()> {
        self.gates
            .push(GateM::AddConstant(ty, dst, left, Box::new(right)));
        Ok(())
    }
    fn mulc(&mut self, ty: TypeId, dst: WireId, left: WireId, &right: &Number) -> eyre::Result<()> {
        self.gates
            .push(GateM::MulConstant(ty, dst, left, Box::new(right)));
        Ok(())
    }
    fn copy(&mut self, ty: TypeId, dst: WireId, src: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::Copy(ty, dst, src));
        Ok(())
    }
    fn constant(&mut self, ty: TypeId, dst: WireId, &src: &Number) -> eyre::Result<()> {
        self.gates.push(GateM::Constant(ty, dst, Box::new(src)));
        Ok(())
    }
    fn public_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::Instance(ty, dst));
        Ok(())
    }
    fn private_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::Witness(ty, dst));
        Ok(())
    }
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> eyre::Result<()> {
        self.gates.push(GateM::AssertZero(ty, src));
        Ok(())
    }
    fn convert(&mut self, dst: TypedWireRange, src: TypedWireRange) -> eyre::Result<()> {
        // read the output wires
        let ty_out = dst.ty;
        let out_first = dst.range.start;
        let out_last = dst.range.end;

        // read the input wires
        let ty_in = src.ty;
        let in_first = src.range.start;
        let in_last = src.range.end;

        self.gates.push(GateM::Conv(Box::new((
            ty_out,
            (out_first, out_last),
            ty_in,
            (in_first, in_last),
        ))));
        Ok(())
    }
    fn call(
        &mut self,
        dst: &[WireRange],
        name: Identifier,
        args: &[WireRange],
    ) -> eyre::Result<()> {
        let mut outids = Vec::with_capacity(dst.len());
        for o in dst {
            outids.push((o.start, o.end));
        }

        // read the input wires
        let mut inids = Vec::with_capacity(args.len());
        for i in args {
            inids.push((i.start, i.end));
        }

        let name = std::str::from_utf8(name)?.into();
        let fun_id = self.fun_store.name_to_fun_id(&name)?;
        self.gates
            .push(GateM::Call(Box::new((fun_id, outids, inids))));
        Ok(())
    }
}

impl RelationVisitor for TextRelation {
    type FBV<'a> = Self;

    fn define_function<BodyCb>(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: BodyCb,
    ) -> eyre::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> eyre::Result<()>,
    {
        let mut body_struct = TextRelation::new(self.type_store.clone(), self.fun_store.clone());
        body(&mut body_struct)?;

        let mut output_counts = vec![];
        for o in outputs {
            output_counts.push((o.ty, o.count));
        }

        let mut input_counts = vec![];
        for inp in inputs {
            input_counts.push((inp.ty, inp.count));
        }

        let name_s: String = std::str::from_utf8(name)?.into();
        let fun_body = FuncDecl::new_function(body_struct.gates, output_counts, input_counts);
        info!(
            "function {:?} args_size:{:?} body_max:{:?} type_ids:{:?}",
            name_s,
            fun_body.compiled_info.args_count,
            fun_body.compiled_info.body_max,
            fun_body.compiled_info.type_ids
        );
        self.fun_store.insert(name_s, fun_body)?;
        Ok(())
    }

    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: PluginBinding,
    ) -> eyre::Result<()> {
        let name_s: String = std::str::from_utf8(name)?.into();

        let mut output_counts = vec![];
        for output in outputs {
            output_counts.push((output.ty, output.count));
        }

        let mut input_counts = vec![];
        for input in inputs {
            input_counts.push((input.ty, input.count));
        }

        let fun_body = FuncDecl::new_plugin(
            output_counts,
            input_counts,
            body.plugin_type.name,
            body.plugin_type.operation,
            body.plugin_type.args,
            vec![], // TODO: Add them !
            vec![], // TODO: Add them!
            &self.type_store,
            &self.fun_store,
        )?;

        info!(
            "plugin {:?} args_size:{:?} body_max:{:?} type_ids:{:?}",
            name_s,
            fun_body.compiled_info.args_count,
            fun_body.compiled_info.body_max,
            fun_body.compiled_info.type_ids
        );
        self.fun_store.insert(name_s, fun_body)?;
        Ok(())
    }
}
