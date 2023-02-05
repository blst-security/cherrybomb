use crate::config::AuthType;

use super::*;
use base64::encode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Custom {
    dm: QuePay,
    name: String,
    value: String,
}
impl Custom {
    pub fn from_3_vals(vals: Vec<&str>) -> Self {
        if vals.len() != 3 {
            panic!("Authentication doesn't match Cherrybomb's scheme!");
        }
        let dm = match vals[0].trim().to_lowercase().as_str() {
            "headers" => QuePay::Headers,
            "path" => QuePay::Path,
            "query" => QuePay::Query,
            "payload" => QuePay::Payload,
            _ => QuePay::None,
        };
        Custom {
            dm,
            name: vals[1].to_string(),
            value: vals[2].to_string(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Authorization {
    Authorization(Auth),
    JWT(String),
    APIKey(String),
    Cookie(String),
    Custom(Custom),
    None,
}
impl Default for Authorization {
    fn default() -> Self {
        Self::None
    }
}
impl Authorization {
    pub fn from_parts(tp: &AuthType, value: String) -> Self {
        match tp {
            AuthType::Basic => {
                let vals: Vec<&str> = value.split(':').collect();
                Self::Authorization(Auth::Basic(vals[0].to_string(), vals[1].to_string()))
            }
            AuthType::Bearer => Self::Authorization(Auth::Bearer(value)),
            AuthType::Header => {
                let vals: Vec<&str> = value.split(':').collect();
                Self::Custom(Custom {
                    dm: QuePay::Headers,
                    name: vals[0].to_string(),
                    value: vals[1].to_string(),
                })
            }
            AuthType::Cookie => Self::Cookie(value),
            _ => Self::None,
        }
    }
    pub fn get_auth(&self) -> Option<RequestParameter> {
        match self {
            Self::Authorization(Auth::Basic(username, password)) => Some(RequestParameter {
                dm: QuePay::Headers,
                name: String::from("Authorization"),
                value: format!("Basic {}", encode(format!("{username}:{password}"))),
            }),
            Self::Authorization(Auth::Bearer(token)) => Some(RequestParameter {
                dm: QuePay::Headers,
                name: String::from("Authorization"),
                value: format!("Bearer {token}"),
            }),
            Self::JWT(token) => Some(RequestParameter {
                dm: QuePay::Headers,
                name: String::from("jwt"),
                value: token.to_string(),
            }),
            Self::APIKey(key) => Some(RequestParameter {
                dm: QuePay::Headers,
                name: String::from("X-API-Key"),
                value: key.to_string(),
            }),
            Self::Cookie(cookie) => Some(RequestParameter {
                dm: QuePay::Headers,
                name: String::from("Cookie"),
                value: cookie.to_string(),
            }),
            Self::Custom(custom) => Some(RequestParameter {
                dm: custom.dm,
                name: custom.name.clone(),
                value: custom.value.clone(),
            }),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Auth {
    Basic(String, String),
    Bearer(String),
    Other,
}
impl Default for Auth {
    fn default() -> Self {
        Self::Other
    }
}
