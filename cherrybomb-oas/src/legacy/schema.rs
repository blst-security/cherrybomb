use super::refs::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SchemaStrInt {
    Int(i64),
    Str(String),
    Bool(bool),
}
impl Default for SchemaStrInt {
    fn default() -> Self {
        Self::Int(0)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AddProps {
    Bool(bool),
    Schema(Box<Schema>),
}
impl Default for AddProps {
    fn default() -> Self {
        Self::Bool(true)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Schema {
    pub title: Option<String>,
    #[serde(rename = "multipleOf")]
    pub multiple_of: Option<i64>,
    pub maximum: Option<f64>,
    pub minimum: Option<f64>,
    #[serde(rename = "exclusiveMaximum")]
    pub exclusive_maximum: Option<String>,
    #[serde(rename = "maxLength")]
    pub max_length: Option<i64>,
    #[serde(rename = "minLength")]
    pub min_length: Option<i64>,
    //String - STAY AWAY!(regex)
    pub pattern: Option<String>,
    #[serde(rename = "maxItem")]
    pub max_items: Option<i64>,
    #[serde(rename = "minItem")]
    pub min_items: Option<i64>,
    #[serde(rename = "uniqueItem")]
    pub unique_items: Option<String>,
    #[serde(rename = "maxProperties")]
    pub max_properties: Option<i64>,
    #[serde(rename = "minProperties")]
    pub min_properties: Option<i64>,
    //Array
    pub items: Option<Box<SchemaRef>>,
    pub required: Option<Vec<String>>,
    #[serde(rename = "enum")]
    pub schema_enum: Option<Vec<Option<SchemaStrInt>>>,
    #[serde(rename = "type")]
    pub schema_type: Option<String>,
    #[serde(rename = "allOf")]
    pub all_of: Option<Vec<SchemaRef>>,
    #[serde(rename = "oneOf")]
    pub one_of: Option<Vec<SchemaRef>>,
    #[serde(rename = "anyOf")]
    pub any_of: Option<Vec<SchemaRef>>,
    pub not: Option<Box<SchemaRef>>,
    //object
    pub properties: Option<HashMap<String, SchemaRef>>,
    #[serde(rename = "additionalProperties")]
    pub additional_properties: Option<AddProps>,
    pub description: Option<String>,
    pub format: Option<String>,
    pub default: Option<SchemaStrInt>,
    pub example: Option<Value>,
    //not in swagger
}
/*
pub struct SchemaLoc{
    schema:SchemaRef,
    location:&'static str,
}
impl Schema{

    pub fn schemas(&self)->Vec<SchemaLoc>{
        let mut schemas = vec![];
        if let Some(all) = &self.all_of{
            for s in all {
                schemas.push(SchemaLoc{
                    schema:s.clone(),
                    location:"all",
                });
            }
        }
        if let Some(any) = &self.any_of{
            for s in any {
                schemas.push(SchemaLoc{
                    schema:s.clone(),
                    location:"any",
                });
            }
        }
        if let Some(one) = &self.one_of{
            for s in one {
                schemas.push(SchemaLoc{
                    schema:s.clone(),
                    location:"one",
                });
            }
        }
        /*
        if let Some(not) = &self.not{
            for s in not {
                schemas.push(SchemaLoc{
                    schema:s.clone(),
                    location:"not",
                });
            }
        }*/
        if let Some(props) = &self.properties{
            for (st,s) in props {
                schemas.push(SchemaLoc{
                    schema:s.clone(),
                    location:"props",
                });
            }
        }
        schemas
    }
}*/
