use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

// https://spec.openapis.org/oas/v3.1.0#request-body-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RequestBody {
    pub description: Option<String>,
    pub content: HashMap<String, crate::new_oas::media_type::MediaType>,
    pub required: Option<bool>,
    pub extensions: Option<HashMap<String, Value>>,
}