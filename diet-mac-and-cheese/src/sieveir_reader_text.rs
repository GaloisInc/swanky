//! SIEVE IR reader in text format.

use crate::circuit_ir::TapeT;
use crate::circuit_ir::{FunStore, FuncDecl, GateM, TypeStore};
use eyre::{bail, Result};
use log::info;
use mac_n_cheese_sieve_parser::text_parser::ValueStreamReader;
use mac_n_cheese_sieve_parser::ValueStreamKind;
use mac_n_cheese_sieve_parser::ValueStreamReader as VSR;
use mac_n_cheese_sieve_parser::{
    ConversionSemantics, FunctionBodyVisitor, Identifier, Number, PluginBinding, RelationVisitor,
    TypeId, TypedCount, TypedWireRange, WireId, WireRange,
};
use std::collections::VecDeque;
use std::fs::File;
use std::path::Path;

pub struct InputText {
    reader: ValueStreamReader<File>,
    queue: VecDeque<Number>,
}

impl InputText {
    pub fn new_private_inputs(path: &Path) -> Result<Self> {
        let reader = ValueStreamReader::open(ValueStreamKind::Private, path)?;

        let mut private_inputs = Self {
            reader,
            queue: Default::default(),
        };
        private_inputs.load_more_in_queue()?;
        Ok(private_inputs)
    }

    pub fn new_public_inputs(path: &Path) -> Result<Self> {
        let reader = ValueStreamReader::open(ValueStreamKind::Public, path)?;

        let mut private_inputs = Self {
            reader,
            queue: Default::default(),
        };
        private_inputs.load_more_in_queue()?;
        Ok(private_inputs)
    }

    fn next_one(&mut self) -> Result<Option<Number>> {
        if let Some(n) = self.queue.pop_front() {
            return Ok(Some(n));
        }

        // the queue is empty let's load some more
        self.load_more_in_queue()?;

        if let Some(n) = self.queue.pop_front() {
            Ok(Some(n))
        } else {
            Ok(None)
        }
    }

    /// Load more instances or witnesses in the internal queue
    fn load_more_in_queue(&mut self) -> Result<Option<()>> {
        for i in 0..(1 << 16) {
            if let Some(v) = self.reader.next()? {
                self.queue.push_back(v);
            } else if i > 0 {
                return Ok(Some(()));
            } else {
                return Ok(None);
            }
        }
        Ok(Some(()))
    }
}

impl TapeT for InputText {
    fn pop(&mut self) -> Option<Number> {
        match self.next_one() {
            Ok(r) => r,
            Err(_) => None,
        }
    }

    fn pop_many(&mut self, num: u64) -> Option<Vec<Number>> {
        let mut numbers = Vec::with_capacity(num as usize);
        for _ in 0..num {
            numbers.push(self.pop()?);
        }
        Some(numbers)
    }
}

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
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> Result<()> {
        self.gates.push(GateM::New(ty, first, last));
        Ok(())
    }
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> Result<()> {
        self.gates.push(GateM::Delete(ty, first, last));
        Ok(())
    }
    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> Result<()> {
        self.gates.push(GateM::Add(ty, dst, left, right));
        Ok(())
    }
    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> Result<()> {
        self.gates.push(GateM::Mul(ty, dst, left, right));
        Ok(())
    }
    fn addc(&mut self, ty: TypeId, dst: WireId, left: WireId, &right: &Number) -> Result<()> {
        self.gates
            .push(GateM::AddConstant(ty, dst, left, Box::new(right)));
        Ok(())
    }
    fn mulc(&mut self, ty: TypeId, dst: WireId, left: WireId, &right: &Number) -> Result<()> {
        self.gates
            .push(GateM::MulConstant(ty, dst, left, Box::new(right)));
        Ok(())
    }
    fn copy(&mut self, ty: TypeId, dst: WireRange, src: &[WireRange]) -> Result<()> {
        self.gates.push(GateM::Copy(
            ty,
            (dst.start, dst.end),
            Box::new(src.iter().map(|wr| (wr.start, wr.end)).collect()),
        ));
        Ok(())
    }
    fn constant(&mut self, ty: TypeId, dst: WireId, &src: &Number) -> Result<()> {
        self.gates.push(GateM::Constant(ty, dst, Box::new(src)));
        Ok(())
    }
    fn public_input(&mut self, ty: TypeId, dst: WireRange) -> Result<()> {
        self.gates.push(GateM::Instance(ty, (dst.start, dst.end)));
        Ok(())
    }
    fn private_input(&mut self, ty: TypeId, dst: WireRange) -> Result<()> {
        self.gates.push(GateM::Witness(ty, (dst.start, dst.end)));
        Ok(())
    }
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> Result<()> {
        self.gates.push(GateM::AssertZero(ty, src));
        Ok(())
    }
    fn convert(
        &mut self,
        dst: TypedWireRange,
        src: TypedWireRange,
        semantics: ConversionSemantics,
    ) -> Result<()> {
        if let ConversionSemantics::Modulus = semantics {
            bail!("Diet Mac'n'Cheese only supports no-modulus conversion semantics")
        }

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
    fn call(&mut self, dst: &[WireRange], name: Identifier, args: &[WireRange]) -> Result<()> {
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
    ) -> Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> Result<()>,
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
    ) -> Result<()> {
        let name_s: String = std::str::from_utf8(name)?.into();

        let mut output_counts = vec![];
        for output in outputs {
            output_counts.push((output.ty, output.count));
        }

        let mut input_counts = vec![];
        for input in inputs {
            input_counts.push((input.ty, input.count));
        }

        let mut public_count = vec![];
        for p in body.public_counts.iter() {
            public_count.push((p.ty, p.count));
        }
        let mut private_count = vec![];
        for p in body.private_counts.iter() {
            private_count.push((p.ty, p.count));
        }

        let fun_body = FuncDecl::new_plugin(
            output_counts,
            input_counts,
            body.plugin_type.name,
            body.plugin_type.operation,
            body.plugin_type.args,
            public_count,
            private_count,
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
