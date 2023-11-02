use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Paths {
    #[serde(flatten)]
    pub paths: HashMap<String, PathItem>,
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathItem {
    pub item_ref: Option<RelReference>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub get: Option<Operation>,
    pub put: Option<Operation>,
    pub post: Option<Operation>,
    pub delete: Option<Operation>,
    pub options: Option<Operation>,
    pub head: Option<Operation>,
    pub patch: Option<Operation>,
    pub trace: Option<Operation>,
    pub servers: Option<Vec<crate::new_oas::server::Server>>,
    pub parameters: Option<Vec<ParamRef>>,
}

enum ParamRef {
    Ref(RelReference),
    Param(Parameter),
}

pub struct Operation {

}


