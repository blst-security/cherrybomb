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