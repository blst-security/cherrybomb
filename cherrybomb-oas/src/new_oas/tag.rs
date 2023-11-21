use serde::{Deserialize, Serialize};

// https://spec.openapis.org/oas/v3.1.0#tag-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Tag {
    pub name: String,
    pub description: Option<String>,
    pub external_docs: Option<crate::new_oas::external_docs::ExternalDocs>,
    pub extensions: Option<serde_json::Value>,
}
