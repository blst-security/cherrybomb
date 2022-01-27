use base64::encode;
use mapper::digest::Header;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Authorization {
    Authorization(Auth),
    JWT(String),
    APIKey(String),
    None,
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
    pub fn get_header(&self) -> Option<Header> {
        match self {
            Self::Authorization(Auth::Basic(username, password)) => Some(Header {
                name: String::from("Authorization"),
                value: format!("Basic {}", encode(format!("{}:{}", username, password))),
            }),
            Self::Authorization(Auth::Bearer(token)) => Some(Header {
                name: String::from("Authorization"),
                value: format!("Bearer {}", token),
            }),
            Self::JWT(token) => Some(Header {
                name: String::from("jwt"),
                value: token.to_string(),
            }),
            Self::APIKey(key) => Some(Header {
                name: String::from("X-API-Key"),
                value: key.to_string(),
            }),
            _ => None,
        }
    }
    pub fn is_api_key(&self) -> bool {
        matches!(self,Self::APIKey(_))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Auth {
    Basic(String, String),
    Bearer(String),
    /*
    APIKey(String),
    Digest(String,String,String),
    OAuth2(String),
    Hawk(String,String,String),
    AWS(String,String),*/
    Other,
}
impl Default for Auth {
    fn default() -> Self {
        Self::Other
    }
}
/*
impl Auth{
    pub fn authenticate(&self){
        match self{
           Self::Basic(username,password)=>(),
           Self::Bearer(token)=>(),
           Self::APIKey(key)=>(),
           Self::Digest(username,password,realm)=>(),
           Self::OAuth2(access_token)=>(),
           Self::Hawk(id,key,algorithm)=>(),
           Self::AWS(access_key,secret_key)=>(),
           Self::Other=>(),
        }
    }
}*/
