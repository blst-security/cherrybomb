use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ExternalDocs {
    pub description: Option<String>,
    pub url: String,
}