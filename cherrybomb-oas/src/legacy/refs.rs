use super::legacy_oas::*;
use super::param::*;
use super::schema::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Reference {
    #[serde(rename = "$ref")]
    pub param_ref: String,
}
impl Reference {
    pub fn get<T>(&self, swagger: &Value) -> T
    where
        T: std::fmt::Debug
            + Clone
            + Serialize
            + PartialEq
            + Default
            + for<'de> serde::Deserialize<'de>,
    {
        if self.param_ref.starts_with('#') {
            let mut val = swagger;
            let split = self.param_ref.split('/').collect::<Vec<&str>>()[1..].to_vec();
            for s in split {
                val = &val[s];
            }
            serde_json::from_value(val.clone()).unwrap()
        } else {
            todo!(
                "external references are not supported yet: {:?}",
                self.param_ref
            )
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ParamRef {
    Ref(Reference),
    Param(Box<Parameter>),
}
impl Default for ParamRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl ParamRef {
    pub fn inner(&self, swagger: &Value) -> Parameter {
        match self {
            Self::Param(p) => *p.clone(),
            Self::Ref(r) => r.get::<Parameter>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ReqRef {
    Ref(Reference),
    Body(Box<ReqBody>),
}
impl Default for ReqRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl ReqRef {
    pub fn inner(&self, swagger: &Value) -> ReqBody {
        match self {
            Self::Body(p) => *p.clone(),
            Self::Ref(r) => r.get::<ReqBody>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SchemaRef {
    Ref(Reference),
    Schema(Box<Schema>),
}
impl Default for SchemaRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl SchemaRef {
    pub fn inner(&self, swagger: &Value) -> Schema {
        match self {
            Self::Schema(p) => {
                //println!("{:?}",p);
                *p.clone()
            }
            Self::Ref(r) => r.get::<Schema>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HeaderRef {
    Ref(Reference),
    Header(Box<Header>),
}
impl Default for HeaderRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl HeaderRef {
    pub fn inner(&self, swagger: &Value) -> Header {
        match self {
            Self::Header(p) => *p.clone(),
            Self::Ref(r) => r.get::<Header>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ResponseRef {
    Ref(Reference),
    Response(Box<Response>),
}
impl Default for ResponseRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl ResponseRef {
    pub fn inner(&self, swagger: &Value) -> Response {
        match self {
            Self::Response(p) => *p.clone(),
            Self::Ref(r) => r.get::<Response>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LinkRef {
    Ref(Reference),
    Link(Box<Link>),
}
impl Default for LinkRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl LinkRef {
    pub fn inner(&self, swagger: &Value) -> Link {
        match self {
            Self::Link(p) => *p.clone(),
            Self::Ref(r) => r.get::<Link>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SecSchemeRef {
    Ref(Reference),
    SecScheme(Box<SecScheme>),
}
impl Default for SecSchemeRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl SecSchemeRef {
    pub fn inner(&self, swagger: &Value) -> SecScheme {
        match self {
            Self::SecScheme(p) => *p.clone(),
            Self::Ref(r) => r.get::<SecScheme>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CallbackRef {
    Ref(Reference),
    CallbackComp(Box<CallbackComp>),
}
impl Default for CallbackRef {
    fn default() -> Self {
        Self::Ref(Reference::default())
    }
}
#[allow(unused)]
impl CallbackRef {
    pub fn inner(&self, swagger: &Value) -> CallbackComp {
        match self {
            Self::CallbackComp(p) => *p.clone(),
            Self::Ref(r) => r.get::<CallbackComp>(swagger),
        }
    }
}
