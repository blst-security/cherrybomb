use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// https://spec.openapis.org/oas/v3.1.0#server-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Server {
    #[serde(rename(deserialize = "url"))]
    pub base_url: String,
    pub description: Option<String>,
    pub variables: Option<HashMap<String, ServerVariable>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ServerVariable {
    #[serde(rename = "enum")]
    pub var_enum: Option<Vec<String>>,
    pub default: String,
    pub description: Option<String>,
}

