use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Encoding {
    pub content_type: Option<String>,
    pub headers: Option<HashMap<String, RelRef>>,
    pub style: Option<String>,
    pub explode: Option<bool>,
    pub allow_reserved: Option<bool>,
    pub extensions: Option<HashMap<String, Value>>,
}
