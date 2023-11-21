use serde::{Deserialize, Serialize};

// https://spec.openapis.org/oas/v3.1.0#external-documentation-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ExternalDocs {
    pub description: Option<String>,
    pub url: String,
}