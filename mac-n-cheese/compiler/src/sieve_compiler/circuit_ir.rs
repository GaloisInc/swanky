use super::supported_fields::FieldIndexedArray;

use mac_n_cheese_sieve_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_wire_map::WireId;

use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::supported_fields::{
    CompilerField, FieldGenericCoproduct, FieldGenericIdentity, FieldGenericProduct, FieldType,
};

mod reader;

macro_rules! define_field_instruction {
    (
        pub enum $FieldInstruction:ident<$FE:ident : CompilerField> {
            $(
                $variant:ident {
                    $( $field:ident : $ty:ident),*
                    $(,)?
                }
            ),*
            $(,)?
        }
    ) => {
        #[derive(Debug, Clone, Copy)]
        pub enum $FieldInstruction<$FE: CompilerField> {
            $($variant { $($field:$ty),* }),*
        }
        #[allow(non_snake_case)]
        #[derive(Clone, Default)]
        pub struct FieldInstructions<$FE: CompilerField> {
            opcodes: Vec<u8>,
            WireId: Vec<WireId>,
            $FE: Vec<$FE>,
        }
        #[allow(non_snake_case)]
        impl<$FE: CompilerField> FieldInstructions<$FE> {
            pub fn push(&mut self, insn: &$FieldInstruction<$FE>) {
                let opcode = 0;
                $(
                    if let $FieldInstruction::$variant { $($field),* } = insn {
                        self.opcodes.push(opcode);
                        $(self.$ty.push(*$field);)*
                        return;
                    }
                    let opcode = opcode + 1;
                )*
                let _ = opcode;
                unreachable!()
            }
            #[allow(unused)]
            pub fn len(&self) -> usize {
                self.opcodes.len()
            }
            pub fn iter(&self) -> impl Iterator<Item = FieldInstruction<$FE>> + '_ {
                struct Iters<'a, $FE: CompilerField> {
                    WireId: std::slice::Iter<'a, WireId>,
                    $FE: std::slice::Iter<'a, $FE>,
                }
                let mut iters = Iters {
                    WireId: self.WireId.iter(),
                    $FE: self.$FE.iter(),
                };
                self.opcodes.iter().copied().map(move |opcode| {
                    let current_opcode = 0;
                    $(
                        if opcode == current_opcode {
                            $(let $field = *iters.$ty.next().unwrap();)*
                            return $FieldInstruction::$variant { $($field),* };
                        }
                        let current_opcode = current_opcode + 1;
                    )*
                    let _ = current_opcode;
                    panic!("invalid opcode {opcode}")
                })
            }
        }
    };
}

// TODO: consider treating dst separately.
define_field_instruction! {
    pub enum FieldInstruction<FE: CompilerField> {
        Constant { dst: WireId, src: FE },
        AssertZero { src: WireId },
        Copy { dst: WireId, src: WireId },
        Add { dst: WireId, left: WireId, right: WireId },
        Mul { dst: WireId, left: WireId, right: WireId },
        AddConstant { dst: WireId, left: WireId, right: FE },
        MulConstant { dst: WireId, left: WireId, right: FE },
        GetPublicInput { dst: WireId },
        GetWitness { dst: WireId },
        Alloc { first: WireId, last: WireId },
        Free { first: WireId, last: WireId },
    }
}
field_generic_type!(pub FieldInstructionsTy<FE: CompilerField> => FieldInstructions<FE>);

impl<FE: CompilerField> Debug for FieldInstructions<FE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WireRange {
    pub start: WireId,
    pub inclusive_end: WireId,
}
impl WireRange {
    pub fn len(&self) -> u64 {
        if self.inclusive_end >= self.start {
            (self.inclusive_end - self.start) + 1
        } else {
            0
        }
    }
}

pub type UserDefinedFunctonId = usize;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FunctionId {
    UserDefined(UserDefinedFunctonId),
}

#[derive(Debug)]
pub struct CounterInfo {
    pub num_env_for_field: usize,
    pub field_type: FieldType,
    pub num_wires: usize,
    pub value: usize,
}

#[derive(Debug)]
pub enum Instruction {
    FieldInstructions(FieldGenericCoproduct<FieldInstructionsTy>),
    FunctionCall {
        function_id: FunctionId,
        out_ranges: FieldIndexedArray<Vec<WireRange>>,
        in_ranges: FieldIndexedArray<Vec<WireRange>>,
        counter_info: Option<CounterInfo>,
    },
    // TODO: It would be better if we could make this a FieldInstruction
    MuxCall {
        permissiveness: Permissiveness,
        field_type: FieldType,
        out_ranges: Vec<WireRange>,
        in_ranges: Vec<WireRange>,
    },
    // TODO: add field switching here
}

#[derive(Clone, Copy, Debug)]
pub enum Type {
    Field(FieldType),
    #[allow(unused)]
    Ram {
        field: FieldType,
        addr_count: usize,
        value_count: usize,
        num_allocs: usize,
        total_alloc_size: usize,
        max_live_alloc_size: usize,
    },
}

pub type PublicInputsNeeded = FieldIndexedArray<u64>;
pub type SizeHint = u64;

#[derive(Default, Debug)]
pub struct FunctionDefinition {
    pub name: String,
    pub input_sizes: Vec<(Type, u64)>,
    pub output_sizes: Vec<(Type, u64)>,
    pub body: Vec<Instruction>,
    pub public_inputs_needed: PublicInputsNeeded,
    pub size_hint: SizeHint,
}

#[derive(Debug, Clone, Copy)]
pub enum Permissiveness {
    Permissive,
    Strict,
}

#[derive(Debug)]
pub struct MuxDefinition {
    name: String,
    permissiveness: Permissiveness,
    field_type: FieldType,
    // cond_count == 1 if field_type is not F2
    cond_count: u64,
    num_branches: usize,
    branch_sizes: Vec<u64>,
}

#[derive(Debug)]
pub struct MapDefinition {
    name: String,
    func: (UserDefinedFunctonId, Arc<FunctionDefinition>),
    num_env: u64,
    iter_count: u64,
    enumerated: bool,
}

pub type NewFunctions = Vec<(UserDefinedFunctonId, Arc<FunctionDefinition>)>;

#[derive(Default, Debug)]
pub struct CircuitChunk {
    pub new_functions: NewFunctions,
    pub new_root_instructions: Vec<Instruction>,
    pub public_inputs: FieldGenericProduct<Vec<FieldGenericIdentity>>,
}
impl CircuitChunk {
    pub fn stream<RR: RelationReader + Send + 'static, VSR: ValueStreamReader + Send + 'static>(
        relation: &Path,
        public_inputs: &[PathBuf],
    ) -> flume::Receiver<eyre::Result<CircuitChunk>> {
        reader::read_circuit::<RR, VSR>(relation, public_inputs)
    }
}
