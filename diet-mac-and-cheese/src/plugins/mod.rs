#[derive(Clone, Debug)]
pub struct PluginType {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    operation: String,
    #[allow(dead_code)]
    params: Vec<String>,
}

impl PluginType {
    pub(crate) fn new(name: String, operation: String, params: Vec<String>) -> Self {
        Self {
            name,
            operation,
            params,
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
