pub mod auth;
pub mod logs;
pub mod req;

use cherrybomb_oas::legacy::legacy_oas::*;
use cherrybomb_oas::legacy::utils;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QuePay {
    Headers,
    Path,
    Query,
    Payload,
    Response,
    None,
}
impl Default for QuePay {
    fn default() -> Self {
        Self::Payload
    }
}
impl fmt::Display for QuePay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Headers => write!(f, "Headers"),
            Self::Path => write!(f, "Path"),
            Self::Query => write!(f, "Query"),
            Self::Payload => write!(f, "Request Payload"),
            Self::Response => write!(f, "Response Payload"),
            Self::None => write!(f, ""),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct MHeader {
    pub name: String,
    pub value: String,
}
impl MHeader {
    pub fn from(name: &str, value: &str) -> MHeader {
        MHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RequestParameter {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing)]
    pub dm: QuePay,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackResponse {
    pub status: u16,
    pub payload: String,
    pub headers: HashMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackRequest {
    pub servers: Vec<Server>,
    pub path: String,
    pub parameters: Vec<RequestParameter>,
    pub payload: String,
    pub auth: auth::Authorization,
    pub method: utils::Method,
    pub headers: Vec<MHeader>,
}
