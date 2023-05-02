use super::lpn_params::LpnParams;
use generic_array::typenum::Unsigned;
use ocelot::ot::explicit_round::{KosReceiver, KosReceiverStage2, KosSender};
use scuttlebutt::{
    field::{Degree, DegreeModulo, FiniteField, IsSubFieldOf},
    serialization::CanonicalSerialize,
};

#[derive(Debug, Clone, Copy)]
pub struct VoleSizes {
    pub base_voles_needed: usize,
    pub voles_outputted: usize,
    pub(crate) base_uws_size: usize,
    pub(crate) ot_num_choices: usize,
    pub comms_1s: usize,
    pub comms_2r: usize,
    pub comms_3s: usize,
    pub comms_4r: usize,
    pub comms_5s: usize,
}
impl VoleSizes {
    pub(crate) const fn from_lpn_params<VF: FiniteField + IsSubFieldOf<FE>, FE: FiniteField>(
        p: LpnParams,
    ) -> Self {
        // TODO: should we use degree modulo, instead?
        let base_uws_size = p.weight;
        let ot_num_choices = base_uws_size * p.log2m;
        VoleSizes {
            base_voles_needed: p.voles_needed_for_extend(Degree::<FE>::USIZE),
            voles_outputted: p.total_output_voles(),
            base_uws_size,
            ot_num_choices,
            comms_1s: KosReceiver::receive_outgoing_bytes(ot_num_choices)
                + base_uws_size * <VF as CanonicalSerialize>::ByteReprLen::USIZE,
            comms_2r: KosSender::send_outgoing_bytes(ot_num_choices)
                + FE::ByteReprLen::USIZE * base_uws_size,
            comms_3s: KosReceiverStage2::OUTGOING_BYTES
                + 16
                + DegreeModulo::<VF, FE>::USIZE * <VF as CanonicalSerialize>::ByteReprLen::USIZE
                + 32,
            comms_4r: FE::ByteReprLen::USIZE,
            comms_5s: 32,
        }
    }
    pub const fn of<VF: FiniteField + IsSubFieldOf<TF>, TF: FiniteField>() -> Self {
        Self::from_lpn_params::<VF, TF>(super::lpn_params::extend_params(Degree::<TF>::USIZE))
    }
}
