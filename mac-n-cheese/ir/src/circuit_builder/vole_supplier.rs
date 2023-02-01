use crate::compilation_format::{FieldMacType, Type};
use rustc_hash::FxHashMap;
use std::collections::hash_map;

use super::{CircuitBuilder, TaskPrototypeRef, WireSlice};

struct VoleState {
    vole_proto: TaskPrototypeRef,
    current_voles: Vec<WireSlice>,
    // In addition to leftovers letting us avoid waste, they also let us start Fixing before VOLE
    // setup has completed.
    leftovers: Vec<WireSlice>,
    vole_index: usize,
}
pub struct VoleSupplier {
    voles: FxHashMap<FieldMacType, VoleState>,
    vole_concurrency: FxHashMap<FieldMacType, usize>,
    default_vole_concurrency: usize,
    output_buffer: Vec<WireSlice>,
}
impl VoleSupplier {
    pub fn new(
        default_vole_concurrency: usize,
        vole_concurrency: FxHashMap<FieldMacType, usize>,
    ) -> Self {
        Self {
            voles: Default::default(),
            default_vole_concurrency,
            vole_concurrency,
            output_buffer: Default::default(),
        }
    }
    pub fn supply_voles(
        &mut self,
        cb: &mut CircuitBuilder,
        prototype: &TaskPrototypeRef,
    ) -> eyre::Result<&[WireSlice]> {
        assert_eq!(prototype.multi_array_inputs().len(), 1);
        let (field, mut count) = prototype
            .multi_array_inputs()
            .iter()
            .find_map(|input| match input.ty() {
                Type::RandomMac(field) => Some((field, input.count())),
                _ => None,
            })
            .expect("The task prototype doesn't need any random macs!");
        let vole_state = match self.voles.entry(field) {
            hash_map::Entry::Occupied(x) => x.into_mut(),
            hash_map::Entry::Vacant(_) => {
                let prime_field_type = field.prime_field_type();
                let vole_concurrency = self
                    .vole_concurrency
                    .get(&field)
                    .copied()
                    .unwrap_or(self.default_vole_concurrency);
                // TODO: increase the vole extend count here.
                let vole_proto = cb.new_vole_extend_prototype(field, 1)?;
                let mut current_voles = Vec::with_capacity(vole_concurrency);
                if prime_field_type == field {
                    // We generate base VOLEs by using copy base svole.
                    let base_vole_proto = cb.new_copy_base_svole_prototype(field)?;
                    current_voles.push(
                        cb.instantiate(&base_vole_proto, &[], &[])?
                            .outputs(Type::RandomMac(field)),
                    );
                } else {
                    todo!("Recurse to fill up the neccessary VOLEs. But we need a new task");
                }
                let mut leftovers = Vec::new();
                let mut vole_index = 0;
                let voles_needed_for_extend = vole_proto.single_array_inputs()[0].count;
                // vole extend expects a SingleArray input to extend.
                while current_voles.len() < vole_concurrency {
                    let current_vole = &mut current_voles[vole_index];
                    debug_assert!(current_vole.len() >= voles_needed_for_extend);
                    if current_vole.len() >= 2 * voles_needed_for_extend {
                        let new_vole = current_vole.slice(0..voles_needed_for_extend);
                        *current_vole = current_vole.slice(voles_needed_for_extend..);
                        current_voles.push(new_vole);
                    } else {
                        let leftover = current_vole.slice(voles_needed_for_extend..);
                        if leftover.len() > 0 {
                            leftovers.push(leftover);
                        }
                        *current_vole = cb
                            .instantiate(
                                &vole_proto,
                                &[current_vole.slice(0..voles_needed_for_extend)],
                                &[],
                            )?
                            .outputs(Type::RandomMac(field));
                        vole_index += 1;
                    }
                    if vole_index >= current_voles.len() {
                        vole_index = 0;
                    }
                }
                self.voles.insert(
                    field,
                    VoleState {
                        vole_proto,
                        current_voles,
                        leftovers,
                        vole_index,
                    },
                );
                self.voles.get_mut(&field).unwrap()
            }
        };
        self.output_buffer.clear();
        while count > 0 && !vole_state.leftovers.is_empty() {
            let mut leftover = vole_state.leftovers.pop().expect("leftovers isn't empty!");
            let to_take = leftover.len().min(count);
            self.output_buffer.push(leftover.slice(0..to_take));
            leftover = leftover.slice(to_take..);
            if leftover.len() > 0 {
                vole_state.leftovers.push(leftover);
            }
            count -= to_take;
        }
        debug_assert!(count == 0 || vole_state.leftovers.is_empty());
        let voles_needed_for_extend = vole_state.vole_proto.single_array_inputs()[0].count();
        while count > 0 {
            let current_vole = &mut vole_state.current_voles[vole_state.vole_index];
            debug_assert!(current_vole.len() >= voles_needed_for_extend);
            if current_vole.len() == voles_needed_for_extend {
                vole_state.vole_index += 1;
                if vole_state.vole_index == vole_state.current_voles.len() {
                    vole_state.vole_index = 0;
                }
                let current_vole = &mut vole_state.current_voles[vole_state.vole_index];
                assert!(current_vole.len() >= voles_needed_for_extend);
                // We only make new voles on increment
                if current_vole.len() == voles_needed_for_extend {
                    *current_vole = cb
                        .instantiate(&vole_state.vole_proto, &[*current_vole], &[])?
                        .outputs(Type::RandomMac(field));
                }
            } else {
                let to_take = (current_vole.len() - voles_needed_for_extend).min(count);
                self.output_buffer.push(current_vole.slice(0..to_take));
                *current_vole = current_vole.slice(to_take..);
                count -= to_take;
            }
        }
        Ok(&self.output_buffer)
    }
}
