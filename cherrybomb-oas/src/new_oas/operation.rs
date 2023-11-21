use serde::{Deserialize,Serialize};
use std::collections::HashMap;

// https://spec.openapis.org/oas/v3.1.0#operation-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Operation {
    pub tags: Option<Vec<String>>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "externalDocs")]
    pub external_docs: Option<crate::new_oas::external_docs::ExternalDocs>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub parameters: Option<Vec<RelRef>>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<RelRef>,
    pub responses: Option<crate::new_oas::responses::Responses>,
    pub callbacks: Option<HashMap<String, RelRef>>,
    pub deprecated: Option<bool>,
    pub security: Option<Vec<crate::new_oas::security::Security>>,
    pub servers: Option<Vec<crate::new_oas::server::Server>>,
}

