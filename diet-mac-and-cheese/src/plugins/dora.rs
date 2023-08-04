use super::{Plugin, PluginExecution};
use crate::circuit_ir::{
    FunStore, FunctionBody, GateM, GatesBody, TypeId, TypeIdMapping, TypeStore, WireCount,
};
use eyre::{eyre, Result};
use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Debug)]
pub(crate) struct ClauseGuard {
    pub guard: Number,
    pub body: GatesBody,
}

#[derive(Clone, Debug)]
pub struct DisjunctionBody {
    id: usize, // unique id for this instance of the plugin
    cond: WireCount,
    field: TypeId,
    inputs: Box<[WireCount]>,
    outputs: Box<[WireCount]>,
    clauses: Box<[ClauseGuard]>, // clauses in this disjunction
}

impl DisjunctionBody {
    pub(crate) fn type_id_mapping(&self) -> TypeIdMapping {
        let mut mapping = TypeIdMapping::default();
        for clause in self.clauses.iter() {
            for g in clause.body.gates() {
                mapping.set_from_gate(g);
            }
        }
        mapping
    }

    pub(crate) fn id(&self) -> usize {
        self.id
    }

    pub(crate) fn clauses(&self) -> impl Iterator<Item = &ClauseGuard> {
        self.clauses.iter()
    }

    pub(crate) fn field(&self) -> TypeId {
        self.field
    }

    pub(crate) fn inputs(&self) -> WireCount {
        self.inputs.iter().sum()
    }

    pub(crate) fn outputs(&self) -> WireCount {
        self.outputs.iter().sum()
    }

    pub(crate) fn guards(&self) -> impl Iterator<Item = &Number> {
        self.clauses.iter().map(|g| &g.guard)
    }

    pub(crate) fn cond(&self) -> WireCount {
        self.cond
    }
}

// generates unique labels for each instance of the plugin
fn get_dora_id() -> usize {
    static INSTANCE_ID: AtomicUsize = AtomicUsize::new(1);
    INSTANCE_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) struct DisjunctionV0;

impl Plugin for DisjunctionV0 {
    const NAME: &'static str = "galois_disjunction_v0";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
        fun_store: &FunStore,
    ) -> Result<PluginExecution> {
        if operation != "switch" {
            return Err(eyre!(
                "{}: Implementation only handles switches, not: \"{operation}\"",
                Self::NAME,
            ));
        }

        // check that it is only for a single field

        let mut ins = input_counts.into_iter().copied();
        let out = output_counts.into_iter().copied();

        let mut cnts_ins = vec![];
        let mut cnts_out = vec![];

        let (typ_cond, num_cond) = ins.next().ok_or_else(|| {
            eyre!(
                "{}: There must be atleast one input: the switch condition",
                Self::NAME,
            )
        })?;

        for (typ, num) in ins {
            if typ != typ_cond {
                return Err(eyre!(
                    "{}: All inputs must be of the same type as the condition",
                    Self::NAME,
                ));
            }
            cnts_ins.push(num);
        }

        for (typ, num) in out {
            if typ != typ_cond {
                return Err(eyre!(
                    "{}: All inputs must be of the same type as the condition",
                    Self::NAME,
                ));
            }
            cnts_out.push(num);
        }

        let mut params = params.iter();

        // switch mode
        match params.next() {
            Some(PluginTypeArg::String(mode)) => {
                // this could also hold a default (for a default clause for the switch)
                assert_eq!(mode, "strict");
            }
            _ => return Err(eyre!("{}: Invalid mode", Self::NAME,)),
        }

        // retrieve function and guard pairs from parameters
        let mut functions = vec![];
        while let Some(guard) = params.next() {
            // check guard type
            let guard = match guard {
                PluginTypeArg::Number(num) => num,
                _ => return Err(eyre!("guard must be a number")),
            };
            // check function type
            if let Some(PluginTypeArg::String(name)) = params.next() {
                functions.push((guard, name))
            } else {
                return Err(eyre!("function name missing"));
            }
        }

        // retrieve function bodies
        let mut clauses = vec![];
        for (guard, name) in functions.into_iter() {
            let fun_decl = fun_store.get(name)?;
            let gates: &[GateM] = match fun_decl.body() {
                FunctionBody::Gates(gates) => gates.gates(),
                FunctionBody::Plugin(_) => {
                    return Err(eyre!("a clause is a plugin, not supported"));
                }
            };
            clauses.push(ClauseGuard {
                guard: *guard,
                body: GatesBody::new(gates.to_owned()),
            });
        }

        // ensure that #inputs = cond + function #inputs

        // most of the magic happens on the first invocation of the disjunction:
        // at which point we have access to the correct evaluator.
        // a reference to DisjuctionBody is passed to the evaluator which instanciates Dora
        Ok(PluginExecution::Disjunction(DisjunctionBody {
            id: get_dora_id(),
            cond: num_cond,
            field: typ_cond,
            inputs: cnts_ins.into(),
            outputs: cnts_out.into(),
            clauses: clauses.into(),
        }))
    }
}
