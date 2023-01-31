use super::ep::*;
use super::legacy_oas::*;
use super::param::*;
use super::refs::*;
use super::utils::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub type Paths = HashMap<String, PathItem>;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Operation {
    pub tags: Option<Vec<String>>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "externalDocs")]
    pub external_docs: Option<ExternalDocs>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub parameters: Option<Vec<ParamRef>>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<ReqRef>,
    pub responses: Option<Responses>,
    pub callback: Option<Callback>,
    pub deprecated: Option<bool>,
    pub security: Option<Vec<Security>>,
    pub servers: Option<Vec<Server>>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParamType {
    Object(HashMap<String, ParamType>),
    String(Box<ParamType>),
    Integer(Box<ParamType>),
}
#[allow(dead_code)]
impl Operation {
    pub fn responses(&self) -> Responses {
        if let Some(r) = self.responses.clone() {
            r
        } else {
            HashMap::new()
        }
    }
    pub fn params(&self) -> Vec<ParamRef> {
        if let Some(v) = &self.parameters {
            v.to_vec()
        } else {
            vec![]
        }
    }
    //content -> schema -> allOf-> (schemaref struct again) properties -> (schemaref again) ->
    //(schemaref)allOf -> recursive until there are no more refs
    //type is type - object, string, integer
    //type object is map
    //type string
    //format - option - data type format
    //enum - option - vector
    pub fn req_body(&self, swagger: &Value) -> (Option<String>, Option<Param>) {
        if let Some(b) = &self.request_body {
            for (name, m_t) in b.inner(swagger).content {
                if let Some(s) = m_t.schema {
                    let inner = s.inner(swagger);
                    let requireds = if let Some(r) = inner.required.clone() {
                        r
                    } else {
                        vec![]
                    };
                    let p_type = if let Some(t) = inner.schema_type.clone() {
                        t
                    } else {
                        String::new()
                    };
                    let r = Param::required(&inner, &p_type, requireds);
                    return (Some(name), Some(Param::schema_rec(swagger, inner, r)));
                }
            }
            panic!("No media types!");
        } else {
            (None, None)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PathItem {
    #[serde(rename = "$ref")]
    pub item_ref: Option<String>,
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
    pub servers: Option<Vec<Server>>,
    pub parameters: Option<Vec<ParamRef>>,
}
#[allow(dead_code)]
impl PathItem {
    pub fn get_possible_eps(&self, swagger_value: &Value, path: String) -> Vec<Ep> {
        let mut eps = vec![];
        for (method, operation) in self.get_ops() {
            let mut path_params: Vec<Param> = self
                .params()
                .iter()
                .map(|param| {
                    let param = param.inner(swagger_value);
                    let mut param1 = Param::schema_to_params(
                        swagger_value,
                        param.schema(),
                        param.name(),
                        param.required(),
                    );
                    param1.dm = param.from();
                    param1
                })
                .collect();
            path_params.extend(
                operation
                    .params()
                    .iter()
                    .map(|param| {
                        let param = param.inner(swagger_value);
                        let mut param1 = Param::schema_to_params(
                            swagger_value,
                            param.schema(),
                            param.name(),
                            param.required(),
                        );
                        param1.dm = param.from();
                        param1
                    })
                    .collect::<Vec<Param>>(),
            );
            let (req_payload_type, req_payload_params) = operation.req_body(swagger_value);
            let mut res_payload_params = HashMap::new();
            for (status, payload) in operation.responses() {
                if let Some(c) = payload.inner(swagger_value).content {
                    for (_name, m_t) in c {
                        if let Some(s) = m_t.schema {
                            res_payload_params.insert(
                                status.clone(),
                                Param::schema_rec(swagger_value, s.inner(swagger_value), true),
                            );
                        }
                    }
                }
            }
            let servers = if let Some(s) = operation.servers.clone() {
                s.iter().map(|s1| s1.base_url.clone()).collect()
            } else {
                vec![]
            };
            eps.push(Ep {
                path: path.clone(),
                method,
                path_params,
                req_payload_params,
                req_payload_type,
                res_payload_params,
                servers,
            });
        }
        eps
    }
    pub fn get_ops(&self) -> Vec<(Method, &Operation)> {
        let mut vec_op = vec![];
        if self.get.is_some() {
            vec_op.push((Method::GET, self.get.as_ref().unwrap()));
        }
        if self.put.is_some() {
            vec_op.push((Method::PUT, self.put.as_ref().unwrap()));
        }
        if self.post.is_some() {
            vec_op.push((Method::POST, self.post.as_ref().unwrap()));
        }
        if self.delete.is_some() {
            vec_op.push((Method::DELETE, self.delete.as_ref().unwrap()));
        }
        if self.options.is_some() {
            vec_op.push((Method::OPTIONS, self.options.as_ref().unwrap()));
        }
        if self.head.is_some() {
            vec_op.push((Method::HEAD, self.head.as_ref().unwrap()));
        }
        if self.patch.is_some() {
            vec_op.push((Method::PATCH, self.patch.as_ref().unwrap()));
        }
        if self.trace.is_some() {
            vec_op.push((Method::TRACE, self.trace.as_ref().unwrap()));
        }
        vec_op
    }
    pub fn params(&self) -> Vec<ParamRef> {
        if let Some(p) = &self.parameters {
            p.to_vec()
        } else {
            vec![]
        }
    }
    pub fn into_digest_path(self, path_ext: String, swagger: &Value) -> DPath {
        DPath {
            path_ext,
            params: PayloadDescriptor {
                params: self
                    .params()
                    .iter()
                    .map(|p| p.inner(swagger).to_desc())
                    .collect(),
            },
        }
    }
}
