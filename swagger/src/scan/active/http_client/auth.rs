use base64::encode;
use mapper::digest::Header as MHeader;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Authorization {
    Authorization(Auth),
    JWT(String),
    APIKey(String),
    None,
}
impl Default for Authorization {
    fn default() -> Self {
        Self::None
    }
}
impl Authorization {
    pub fn from_parts(tp: &str, value: String) -> Self {
        match tp {
            "0" => {
                let vals: Vec<&str> = value.split(':').collect();
                Self::Authorization(Auth::Basic(vals[0].to_string(), vals[1].to_string()))
            }
            "1" => Self::Authorization(Auth::Bearer(value)),
            "2" => Self::JWT(value),
            "3" => Self::APIKey(value),
            _ => Self::None,
        }
    }
    pub fn get_header(&self) -> Option<MHeader> {
        match self {
            Self::Authorization(Auth::Basic(username, password)) => Some(MHeader {
                name: String::from("Authorization"),
                value: format!("Basic {}", encode(format!("{}:{}", username, password))),
            }),
            Self::Authorization(Auth::Bearer(token)) => Some(MHeader {
                name: String::from("Authorization"),
                value: format!("Bearer {}", token),
            }),
            Self::JWT(token) => Some(MHeader {
                name: String::from("jwt"),
                value: token.to_string(),
            }),
            Self::APIKey(key) => Some(MHeader {
                name: String::from("X-API-Key"),
                value: key.to_string(),
            }),
            _ => None,
        }
    }
    /*
    pub fn is_api_key(&self) -> bool {
        match self {
            Self::APIKey(_) => true,
            _ => false,
        }
    }*/
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
