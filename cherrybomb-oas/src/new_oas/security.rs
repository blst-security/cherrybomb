use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// https://spec.openapis.org/oas/v3.1.0#security-requirement-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Security {
    pub security: Option<HashMap<String, Vec<String>>>,
}