use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Paths {
    #[serde(flatten)]
    pub paths: HashMap<String, PathItem>,
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathItem {
    pub summary: Option<String>,
    pub description: Option<String>,
    pub get: Option<Operation>,
    pub put: Option<Operation>,
    pub post: Option<Operation>,
    pub delete: Option<Operation>,
    pub options: Option<Operation>,
    pub head: Option<Operation>,
    pub patch: Option<Operation>,
    pub trace: Option<Operation>,
    pub servers: Option<Vec<crate::new_oas::server::Server>>,
}

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
    pub responses: Option<Responses>,
    pub callbacks: Option<HashMap<String, RelRef>>,
    pub deprecated: Option<bool>,
    pub security: Option<Vec<crate::new_oas::security::Security>>,
    pub servers: Option<Vec<crate::new_oas::server::Server>>,
}

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



#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MediaType {
pub schema: Option<Schema>,
    pub example: Option<Value>,
    pub examples: Option<HashMap<String, RelRef>>,
    pub encoding: Option<HashMap<String, Encoding>>,
}



