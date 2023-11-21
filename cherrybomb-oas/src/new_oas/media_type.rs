use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::new_oas::schema::Schema;

// https://spec.openapis.org/oas/v3.1.0#media-type-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MediaType {
    pub schema: Option<Schema>,
    pub example: Option<Value>,
    pub examples: Option<HashMap<String, RelRef>>,
    pub encoding: Option<HashMap<String, crate::new_oas::encoding::Encoding>>,
    pub extensions: Option<HashMap<String, Value>>,
}
