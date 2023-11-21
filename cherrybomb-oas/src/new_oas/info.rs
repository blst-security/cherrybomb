use serde::{Deserialize, Serialize};

// https://spec.openapis.org/oas/v3.1.0#info-object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Info {
    pub title: String,
    pub description: Option<String>,
    #[serde(rename = "termsOfService")]
    pub tos: Option<String>,
    pub contact: Option<Contact>,
    pub license: Option<License>,
    pub version: String,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Contact {
    pub name: Option<String>,
    pub url: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct License {
    pub name: String,
    pub url: Option<String>,
}
