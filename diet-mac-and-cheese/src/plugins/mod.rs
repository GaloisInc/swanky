use mac_n_cheese_sieve_parser::PluginTypeArg;

#[derive(Clone, Debug)]
pub struct PluginType {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    operation: String,
    #[allow(dead_code)]
    params: Vec<PluginTypeArg>,
}

impl PluginType {
    pub(crate) fn new(name: String, operation: String, params: Vec<String>) -> Self {
        let params = params
            .into_iter()
            .map(|s| PluginTypeArg::String(s))
            .collect();
        Self {
            name,
            operation,
            params,
        }
    }
}

impl From<mac_n_cheese_sieve_parser::PluginType> for PluginType {
    fn from(ty: mac_n_cheese_sieve_parser::PluginType) -> Self {
        Self {
            name: ty.name,
            operation: ty.operation,
            params: ty.args,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PluginBody {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    operation: String,
}

impl PluginBody {
    pub(crate) fn new(name: String, operation: String) -> Self {
        Self { name, operation }
    }
}

pub(crate) mod mux_v0;
// #[allow(dead_code)]
// pub(crate) mod permutation_check_v1;
