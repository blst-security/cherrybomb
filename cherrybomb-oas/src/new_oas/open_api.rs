use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenAPI {
    pub openapi: String,
    pub info: crate::new_oas::info::Info,
    #[serde(rename = "jsonSchemaDialect")]
    pub json_schema_dialect: Option<String>,
    pub servers: Option<Vec<crate::new_oas::server::Server>>,
    pub paths: Option<crate::new_oas::paths::Paths>,
    pub webhooks: Option<HashMap<String,RelRef>>,
    pub components: Option<crate::new_oas::components::Components>,
    pub security: Option<Vec<crate::new_oas::security::Security>>,
    pub tags: Option<Vec<crate::new_oas::tags::Tag>>,
    pub external_docs: Option<crate::new_oas::external_docs::ExternalDocs>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}