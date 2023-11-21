use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// https://spec.openapis.org/oas/v3.1.0#responses-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Responses {
    #[serde(rename = "default")]
    pub default: Option<RelRef>,
    pub responses: Option<HashMap<String, RelRef>>,
    pub extensions: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Response {
    pub description: String,
    pub headers: Option<HashMap<String, RelRef>>,
    pub content: Option<HashMap<String, MediaType>>,
    pub links: Option<HashMap<String, RelRef>>,
    pub extensions: Option<HashMap<String, Value>>,
}