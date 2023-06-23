use super::Plugin;

pub(crate) struct VectorsV1;

impl Plugin for VectorsV1 {
    const NAME: &'static str = "vectors_v1";

    fn gates_body(
            operation: &str,
            params: &[String],
            count: u64,
            output_counts: &[(crate::circuit_ir::TypeId, crate::circuit_ir::WireCount)],
            input_counts: &[(crate::circuit_ir::TypeId, crate::circuit_ir::WireCount)],
            type_store: &crate::circuit_ir::TypeStore,
        ) -> eyre::Result<crate::circuit_ir::GatesBody> {
        todo!()
    }
}