use serde::{Deserialize,Serialize};
use serde_json::Value;
use std::collections::HashMap;

// https://spec.openapis.org/oas/v3.1.0#parameter-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Parameter{
    pub name: String,
    #[serde(rename = "in")]
    pub in_: String,
    pub description: Option<String>,
    pub required: Option<bool>,
    pub deprecated: Option<bool>,
    #[serde(rename = "allowEmptyValue")]
    pub allow_empty_value: Option<bool>,
    pub style: Option<String>,
    pub explode: Option<bool>,
    #[serde(rename = "allowReserved")]
    pub allow_reserved: Option<bool>,
    pub schema: Option<Schema>,
    pub example: Option<Value>,
    pub examples: Option<HashMap<String, RelRef>>,
    pub content: Option<HashMap<String, MediaType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MediaType {
    pub schema: Option<Schema>,
    pub example: Option<Value>,
    pub examples: Option<HashMap<String, RelRef>>,
    pub encoding: Option<HashMap<String, Encoding>>,
}

