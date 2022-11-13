use std::collections::HashMap;

use super::http_client::RequestParameter;
use crate::{
    active::http_client::AttackRequest,
    path::Operation,
    refs::{ResponseRef, SchemaRef},
    Authorization, Method, QuePay, Server,
};
use reqwest::{Client, Request, RequestBuilder, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn recursive_func_to_find_param(
    swagger: &Value,
    schema: SchemaRef,
    vec_of_param: &mut Vec<String>,
) -> Vec<String> {
    let properti_option = schema.inner(swagger).items;
    if let Some(schemaB) = properti_option {
        let propertie = schemaB.inner(swagger).properties.unwrap_or_default();

        for (key, value) in propertie {
            let inner_ref = value.inner(swagger).items;

            if key.contains("id") && inner_ref.is_none() {
                vec_of_param.push(key);
            } else if value.inner(swagger).properties.is_some() {
                recursive_func_to_find_param(swagger, value, vec_of_param);
            }
        }
    }
    let propertie = schema.inner(swagger).properties.unwrap_or_default(); //if let failed
                                                                          //meanning that the schemaref is none so we need build it

    for (key, value) in propertie {
        let inner_ref = value.inner(swagger).items;
        if key.contains("id") && inner_ref.is_none() {
            vec_of_param.push(key);
        } else if value.inner(swagger).properties.is_some() {
            recursive_func_to_find_param(swagger, value, vec_of_param);
        }
    }
    vec_of_param.to_vec()
}

pub fn read_json_func(obj: &Value, element: &String, vector: &mut Vec<String>) -> Vec<String> {
    let st = obj.as_object();
    if let Some(hashmap) = st {
        for (key, value) in hashmap {
            if key.eq(element) {
                if let Some(array) = value.as_array() {
                    for i in array {
                        if let Some(val) = i.as_str() {
                            vector.push(val.to_string());
                        }
                        if let Some(val) = i.as_u64() {
                            vector.push(val.to_string());
                        }
                    }
                }

                if let Some(val) = value.as_str() {
                    vector.push(val.to_string());
                }
                if let Some(val) = value.as_u64() {
                    vector.push(val.to_string());
                }
            }

            read_json_func(value, element, vector);
        }
    }
    return vector.to_vec();
}

pub async fn send_req(
    path: String,
    base: &String,
    element: &String,
    auth: &Authorization,
    server: &Option<Vec<Server>>,
) -> Vec<String> {
    let mut serv = "".to_string();
    let mut collection_of_values: Vec<String> = Vec::new();
    let req = AttackRequest::builder()
        .uri(&server, &path)
        .parameters(vec![])
        .auth(auth.clone())
        .method(Method::GET)
        .headers(vec![])
        .auth(auth.clone())
        .build();
    let res = req.send_request_with_response().await;
    if res.1 {
        let mut object: Value = serde_json::from_str(&res.0).unwrap();
        for i in object.as_array() {
            // take jsonresponse as array
            for x in i.into_iter() {
                read_json_func(&x, element, &mut collection_of_values);
            }
        }
    }

    // println!(
    //     "--------Collections of values before send the main function: {:?}------",
    //     collection_of_values
    // );
    collection_of_values
}

/// This function is used to create a payload for a GET request parameters
pub fn create_payload_for_get(
    swagger: &Value,
    op: &Operation,
    test_value: Option<String>,
) -> Vec<RequestParameter> {
    let mut params_vec = vec![];
    for i in op.params() {
        let parameter = i.inner(swagger);
        let in_var = parameter.param_in;
        let param_name = parameter.name.to_string();
        match in_var.as_str().to_lowercase().trim() {
            "path" => {
                let mut option_example_value = None;
                if let Some(value) = parameter.examples {
                    if let Some((_ex, val)) = value.into_iter().next() {
                        option_example_value = Some(val.value.to_string());
                    }
                }
                if let Some(schema_ref) = parameter.schema {
                    // dbg!(&schema_ref);
                    if let Some(schema_type) = schema_ref.inner(swagger).schema_type {
                        // let val_to_path:String;
                        match schema_type.as_str() {
                            "string" => {
                                let mut example_value = "randomString".to_string();
                                if let Some(val) = option_example_value {
                                    example_value = val;
                                }

                                params_vec.push(RequestParameter {
                                    name: param_name,
                                    value: example_value,
                                    dm: QuePay::Path,
                                });
                            }
                            "integer" => {
                                let mut example_value = "123".to_string();
                                if let Some(val) = option_example_value {
                                    example_value = val;
                                }
                                params_vec.push(RequestParameter {
                                    name: param_name,
                                    value: example_value,
                                    dm: QuePay::Path,
                                });
                            }
                            "boolean" => {
                                let mut example_value = "true".to_string();
                                if let Some(val) = option_example_value {
                                    example_value = val;
                                }

                                params_vec.push(RequestParameter {
                                    name: param_name,
                                    value: example_value,
                                    dm: QuePay::Path,
                                });
                            }
                            _ => (),
                        };
                    } else {
                        let mut example_value = "randomString".to_string();
                        if let Some(val) = option_example_value {
                            example_value = val;
                        }

                        params_vec.push(RequestParameter {
                            name: param_name,
                            value: example_value,
                            dm: QuePay::Path,
                        });
                    }
                }
            }
            "query" => {
                //todo support type
                let mut final_value = "blstpollute".to_string();
                if let Some(ref value) = test_value {
                    if !value.eq(&"".to_string()) {
                        if test_value.as_ref().is_none() {
                            // let mut example_value = "randomString".to_string();
                            //let mut  option_example_value= None  ;
                            if let Some(values) = parameter.examples {
                                if let Some((_ex, val)) = values.into_iter().next() {
                                    final_value = val.value.to_string();
                                }
                            }
                        } else {
                            // unwrap - else clause of is_none
                            final_value = value.to_string();
                        }
                        params_vec.push(RequestParameter {
                            name: param_name,
                            dm: QuePay::Query,
                            value: final_value,
                        });
                    }
                }
            }
            _ => (),
        };
    }
    params_vec
}
