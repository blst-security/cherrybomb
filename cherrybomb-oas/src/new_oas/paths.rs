use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;
use crate::new_oas::operation::Operation;

// https://spec.openapis.org/oas/v3.1.0#paths-object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Paths {
    #[serde(flatten)]
    pub paths: HashMap<String, PathItem>,
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathItem {
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
}



