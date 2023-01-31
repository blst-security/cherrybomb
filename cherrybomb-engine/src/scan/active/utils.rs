use crate::scan::active::http_client::auth::Authorization;
use crate::scan::active::http_client::QuePay;
use crate::scan::active::http_client::{AttackRequest, RequestParameter};
use cherrybomb_oas::legacy::legacy_oas::Server;
use cherrybomb_oas::legacy::path::Operation;
use cherrybomb_oas::legacy::utils::Method;
use serde_json::Value;
use std::collections::HashMap;

pub fn create_payload(
    // this function needs to calls the create hash func from here try to get the value from the hash
    // then if success build requestParameter else then use the get regular function
    swagger: &Value,
    op: &Operation,
    hash_map: &HashMap<String, String>,
    placeholder: Option<String>,
) -> Vec<RequestParameter> {
    let mut params_vec: Vec<RequestParameter> = vec![];

    for i in op.params() {
        let parameter = i.inner(swagger);
        let in_var = parameter.param_in;
        let param_name = parameter.name.to_string();
        if in_var.trim().eq("path") {
            // if param is in path
            if let Some(the_key) = hash_map.iter().find_map(|(key, _val)| {
                //if is match the hashmap
                if key.to_lowercase().eq(&param_name.to_lowercase()) {
                    Some(key)
                } else {
                    None
                }
            }) {
                let param_value = hash_map.get(the_key).unwrap();
                let mut params_vec = vec![];
                params_vec.push(RequestParameter {
                    //push the parameter in the req vec
                    name: param_name,
                    value: param_value.to_string(),
                    dm: QuePay::Path,
                });
                if placeholder.is_some() && placeholder.clone().unwrap().eq("") {
                    //  println!("The placeholder is empty ");

                    // if there is a empty placeholder  and it's match with hashmap so return the vec param
                    return params_vec;
                }
            }
        }
    }

    if placeholder.as_ref().is_some() {
        //   println!("THe placeholder is some");
        // if there is a placeholder value, used  in ssrf or redirection for example
        if !placeholder.clone().unwrap().eq("") {
            //empty quote in placeholder are used only to create a path parameter payload.
            //if there is  placeholder and the value  exist in the hashmap so let's call the second method for paylaod redirection or pollution.
            return create_payload_for_get(swagger, op, placeholder, &mut params_vec);
        }
    } else {
        //The placeholder is none for pollution
        return create_payload_for_get(swagger, op, placeholder, &mut params_vec);
    }
    //println!("END");

    params_vec
}

pub async fn send_req(
    //send request and check the value of specific key, return vec of values
    path: String,
    element: &String,
    auth: &Authorization,
    server: &Option<Vec<Server>>,
) -> Vec<String> {
    let mut collection_of_values: Vec<String> = Vec::new();
    let req = AttackRequest::builder()
        .uri(server, &path)
        .parameters(vec![])
        .auth(auth.clone())
        .method(Method::GET)
        .headers(vec![])
        .auth(auth.clone())
        .build();
    let res = req.send_request_with_response().await;
    if res.1 {
        let object: Value = serde_json::from_str(&res.0).unwrap_or_default();
        if let Some(i) = object.as_array() {
            for x in i.iter() {
                // println!("x: {x:?}");
                read_json_func(x, element, &mut collection_of_values);
            }
        }
    }
    collection_of_values
}

pub fn read_json_func(obj: &Value, element: &String, vector: &mut Vec<String>) -> Vec<String> {
    let st = obj.as_object();
    if let Some(hashmap) = st {
        for (key, value) in hashmap {
            if key.eq(&element.to_lowercase()) {
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
    vector.to_vec()
}

pub fn create_payload_for_get(
    swagger: &Value,
    op: &Operation,
    test_value: Option<String>,
    params_vec: &mut Vec<RequestParameter>,
) -> Vec<RequestParameter> {
    //   let mut params_vec = vec![];
    let mut final_value = "blstparamtopollute".to_string(); //random string use to parameter pollution
    for i in op.params() {
        let parameter = i.inner(swagger);
        let in_var = parameter.param_in;
        let param_name = parameter.name.to_string();
        match in_var.as_str().to_lowercase().trim() {
            "path" => {
                // if the param is in the path
                if !params_vec.iter().any(|s| s.name == param_name) {
                    //  check if there is not  a path parameter already configured so
                    //we check if param_name is not exist in the params_vec

                    let mut option_example_value = None;
                    if let Some(value) = parameter.examples {
                        // if there is an example
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
            }
            "query" => {
                if let Some(ref value) = test_value {
                    // Here in case of ssrf of redirection there is Some(value)
                    if !value.eq(&"".to_string()) {
                        //
                        //    if test_value.as_ref().is_none() {
                        params_vec.push(RequestParameter {
                            name: param_name,
                            dm: QuePay::Query,
                            value: value.to_string(),
                        });
                    } else {
                        //if the placeholder is empty string means that we want to insert example of default values
                        if parameter.required.unwrap_or(false) {
                            //check if the query parameter is mandatory
                            if let Some(values) = parameter.examples {
                                if let Some((_ex, val)) = values.into_iter().next() {
                                    //take example as value
                                    final_value = val.value.to_string();
                                    params_vec.push(RequestParameter {
                                        name: param_name,
                                        dm: QuePay::Query,
                                        value: val.value.to_string(),
                                    });
                                } else {
                                    //if no examples insert randonstring
                                    params_vec.push(RequestParameter {
                                        name: param_name,
                                        dm: QuePay::Query,
                                        value: "randomString".to_string(),
                                    });
                                }
                            }
                        } // if no mandatory continue
                    }
                } else {
                    //if value to test is none, meaning test for pollution

                    params_vec.push(RequestParameter {
                        name: param_name,
                        dm: QuePay::Query,
                        value: final_value.clone(),
                    });
                }
            }
            _ => (),
        };
    }
    params_vec.to_vec()
}
