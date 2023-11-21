use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// https://spec.openapis.org/oas/v3.1.0#components-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Components {
    pub schemas: Option<HashMap<String, Schema>>,
    pub responses: Option<HashMap<String, RelRef>>,
    pub parameters: Option<HashMap<String, RelRef>>,
    pub examples: Option<HashMap<String, RelRef>>,
    pub request_bodies: Option<HashMap<String, RelRef>>,
    pub headers: Option<HashMap<String, RelRef>>,
    pub security_schemes: Option<HashMap<String, RelRef>>,
    pub links: Option<HashMap<String, RelRef>>,
    pub callbacks: Option<HashMap<String, RelRef>>,
    pub extensions: Option<HashMap<String, Value>>,
}