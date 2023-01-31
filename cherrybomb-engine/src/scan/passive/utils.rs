use crate::scan::*;
use cherrybomb_oas::legacy::legacy_oas::*;
use cherrybomb_oas::legacy::param::*;
use cherrybomb_oas::legacy::refs::*;
use cherrybomb_oas::legacy::schema::*;
use cherrybomb_oas::legacy::utils::*;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use url::{ParseError, Url};

pub fn check_servers_for_server_url_rule(
    servers: &[Server],
    location: &str,
    prev_addrs: &mut HashSet<String>,
) -> Vec<Alert> {
    let mut alerts = vec![];
    for server in servers {
        if prev_addrs.get(&server.base_url).is_some() {
            continue;
        } else {
            prev_addrs.insert(server.base_url.clone());
        }
        match Url::parse(&server.base_url) {
            Ok(u) => {
                if u.scheme() == "http" {
                    alerts.push(Alert::new(
                        Level::Low,
                        "Insecure transport, using http instead of https",
                        format!("{}, address:{}", location, server.base_url),
                    ));
                }
            }
            Err(ParseError::RelativeUrlWithoutBase) => continue,
            Err(_) => alerts.push(Alert::new(
                Level::Low,
                "Invalid URL in the server parameter",
                format!("{}, address:{}", location, server.base_url),
            )),
        };
    }
    alerts
}
pub fn get_responses<T>(swagger: &T) -> Vec<(Responses, String)>
where
    T: OAS,
{
    let mut ret = vec![];
    if let Some(components) = &swagger.components() {
        if let Some(responses) = &components.responses {
            ret.push((
                responses.clone(),
                "swagger root components responses".to_string(),
            ));
        }
    }
    for (path, item) in &swagger.get_paths() {
        ret.extend(
            item.get_ops()
                .iter()
                .map(|(m, op)| (op.responses(), format!("swagger path:{path} operation:{m}"))),
        );
    }
    ret
}
pub fn get_params<T>(swagger: &T, swagger_value: &Value) -> Vec<(Param, String)>
where
    T: OAS,
{
    let mut params = vec![];
    for (path, item) in &swagger.get_paths() {
        params.extend(item.params().iter().map(|param| {
            let param = param.inner(swagger_value);
            (
                Param::schema_to_params(
                    swagger_value,
                    param.schema(),
                    param.name(),
                    param.required(),
                ),
                format!("swagger path:{} param:{}", path, param.name()),
            )
        }));
        for (method, operation) in item.get_ops() {
            params.extend(operation.params().iter().map(|param| {
                let param = param.inner(swagger_value);
                (
                    Param::schema_to_params(
                        swagger_value,
                        param.schema(),
                        param.name(),
                        param.required(),
                    ),
                    format!(
                        "swagger path:{} method:{} param:{}",
                        path,
                        method,
                        param.name()
                    ),
                )
            }));
            let (req_payload_type, req_payload_params) = operation.req_body(swagger_value);
            params.extend(req_payload_params.iter().map(|param| {
                (
                    param.clone(),
                    format!("swagger path:{path} request body, payload type:{req_payload_type:?}"),
                )
            }));
            for (status, payload) in operation.responses() {
                if let Some(c) = payload.inner(swagger_value).content {
                    params.extend(c.iter().filter_map(|(name, m_t)| {
                        m_t.schema.as_ref().map(|s| {
                            (
                                Param::schema_rec(swagger_value, s.inner(swagger_value), true),
                                format!(
                                    "swagger path:{path} status:{status} response body, media type:{name}"
                                ),
                            )
                        })
                    }));
                }
            }
        }
    }
    params
}
pub fn param_default_rec(param: &Param, loc: String) -> Vec<Alert> {
    let mut alerts = vec![];
    match &param.value {
        ParamValue::Object | ParamValue::Array => {
            for p in &param.params {
                alerts.extend(param_default_rec(p, loc.clone()));
            }
        }
        /*
        ParamValue::Boolean=>{
            if let SchemaStrInt::Bool(_) = param.default{
                return Alert::new(Level::Low,"Default type does not match parameter type",format!("{} param name:{}",loc,param.name));
            }*/
        ParamValue::Integer(i) => {
            if let Some(sc) = &i.default {
                return match sc {
                    SchemaStrInt::Int(_) => {
                        vec![]
                    }
                    _ => {
                        vec![Alert::new(
                            Level::Low,
                            "Default type does not match parameter type",
                            format!("{} param name:{}", loc, param.name),
                        )]
                    }
                };
            }
        }
        ParamValue::String(s) => {
            if let Some(sc) = &s.default {
                return match sc {
                    SchemaStrInt::Str(_) => {
                        vec![]
                    }
                    _ => {
                        vec![Alert::new(
                            Level::Low,
                            "Default type does not match parameter type",
                            format!("{} param name:{}", loc, param.name),
                        )]
                    }
                };
            }
        }
        _ => {
            return vec![];
        } /*""=>{
              if param.properties.is_some() || param.any_of.is_some() || param.all_of.is_some() || param.one.is_some(){
                  alerts.push(Alert::new(Level::Low,"Object parameter lacks type",format!("{} param name:{}",loc,param.name),PassiveChecks::CheckDefaultType));
              }
          }*/
    };
    alerts
}
pub fn param_enum_rec(param: &Param, loc: String) -> Vec<Alert> {
    let mut alerts = vec![];
    match &param.value {
        ParamValue::Object | ParamValue::Array => {
            for p in &param.params {
                alerts.extend(param_default_rec(p, loc.clone()));
            }
        }
        ParamValue::Integer(i) => {
            if let Some(en) = &i.p_enum {
                for e in en.iter().flatten() {
                    match e {
                        SchemaStrInt::Int(_) => (),
                        _ => {
                            return vec![Alert::new(
                                Level::Low,
                                "Enum type does not match parameter type",
                                format!("{} param name:{}", loc, param.name),
                            )];
                        }
                    }
                }
            }
        }
        ParamValue::String(i) => {
            if let Some(en) = &i.p_enum {
                for e in en.iter().flatten() {
                    match e {
                        SchemaStrInt::Str(_) => (),
                        _ => {
                            return vec![Alert::new(
                                Level::Low,
                                "Enum type does not match parameter type",
                                format!("{} param name:{}", loc, param.name),
                            )];
                        }
                    }
                }
            }
        }
        _ => {
            return vec![];
        } /*""=>{
              if param.properties.is_some() || param.any_of.is_some() || param.all_of.is_some() || param.one.is_some(){
                  alerts.push(Alert::new(Level::Low,"Object parameter lacks type",format!("{} param name:{}",loc,param.name),PassiveChecks::CheckDefaultType));
              }
          }*/
    };
    alerts
}
pub fn additional_properties_test(schema: &Schema, location: String) -> Vec<Alert> {
    let tp = if let Some(t) = &schema.schema_type {
        t
    } else {
        ""
    };
    let mut alerts = vec![];
    match tp.to_lowercase().as_str() {
        "" => {
            alerts.push(Alert::new(
                Level::Low,
                "Object schema without a type",
                location.clone(),
            ));
            if schema.additional_properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema allows for additional properties",
                    location,
                ))
            }
        }
        "object" => {
            if schema.additional_properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema allows for additional properties",
                    location,
                ))
            }
        }
        _ => {}
    };
    alerts
}
pub fn get_auth<T>(swagger: &T) -> Option<HashMap<String, SecSchemeRef>>
where
    T: OAS,
{
    if let Some(components) = &swagger.components() {
        components.security_schemes.clone()
    } else {
        None
    }
}
pub fn get_path_responses<T>(swagger: &T) -> Vec<(String, Method, Vec<Security>, Responses)>
where
    T: OAS,
{
    swagger
        .get_paths()
        .iter()
        .flat_map(|(path, item)| {
            let mut d_vec = vec![];
            for (m, op) in item.get_ops() {
                let sec = if let Some(s) = &op.security {
                    s.to_vec()
                } else {
                    vec![]
                };
                d_vec.push((path.clone(), m, sec, op.responses().clone()));
            }
            d_vec
        })
        .collect()
}
pub fn get_schemas_by_type<T>(swagger: &T, swagger_value: &Value, tp: &str) -> Vec<(Schema, String)>
where
    T: OAS,
{
    let mut schemas = vec![];
    for (path, item) in &swagger.get_paths() {
        for (m, op) in item.get_ops() {
            if let Some(r_body) = &op.request_body {
                let r_body = r_body.inner(swagger_value);
                for (name, m_t) in r_body.content {
                    if let Some(s) = m_t.schema {
                        schemas.extend(get_all_params_by_type(
                            &s.inner(swagger_value),
                            swagger_value,
                            "integer",
                            format!(
                                "swagger root path:{path} method:{m} request body media type:{name}"
                            ),
                        ));
                    }
                }
            }
            for (status, response) in op.responses() {
                let response = response.inner(swagger_value);
                if let Some(content) = response.content {
                    for (name, m_t) in content {
                        if let Some(s) = m_t.schema {
                            schemas.extend(
                                get_all_params_by_type(
                                    &s.inner(swagger_value),
                                    swagger_value,
                                    tp,
                                    format!("swagger root path:{path} method:{m} response status:{status}  media type:{name}")));
                        }
                    }
                }
            }
        }
    }
    schemas
}
pub fn get_all_params_by_type(
    schema: &Schema,
    swagger_value: &Value,
    tp: &str,
    location: String,
) -> Vec<(Schema, String)> {
    let mut schemas = vec![];
    let s_tp = if let Some(t) = &schema.schema_type {
        t
    } else {
        ""
    };
    if s_tp == tp {
        schemas.push((schema.clone(), location.clone()));
    }
    match s_tp.to_lowercase().as_str() {
        "object" | "" | "array" => {
            let any_of = if let Some(a) = &schema.any_of {
                a.to_vec()
            } else {
                vec![]
            };
            let one_of = if let Some(a) = &schema.one_of {
                a.to_vec()
            } else {
                vec![]
            };
            let all_of = if let Some(a) = &schema.all_of {
                a.to_vec()
            } else {
                vec![]
            };
            let props = if let Some(p) = &schema.properties {
                p.clone()
            } else {
                HashMap::new()
            };
            schemas.extend(any_of.iter().flat_map(|a| {
                get_all_params_by_type(&a.inner(swagger_value), swagger_value, tp, location.clone())
            }));
            schemas.extend(all_of.iter().flat_map(|a| {
                get_all_params_by_type(&a.inner(swagger_value), swagger_value, tp, location.clone())
            }));
            schemas.extend(one_of.iter().flat_map(|a| {
                get_all_params_by_type(&a.inner(swagger_value), swagger_value, tp, location.clone())
            }));
            schemas.extend(props.iter().flat_map(|(name, p)| {
                get_all_params_by_type(
                    &p.inner(swagger_value),
                    swagger_value,
                    tp,
                    format!("{location} prop:{name}"),
                )
            }));
        }
        _ => (),
    };
    schemas
}
