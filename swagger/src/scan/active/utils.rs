use std::collections::HashMap;

use super::http_client::RequestParameter;
use crate::{path::Operation, QuePay};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn read_json_func(obj: &Value, element: &String) -> Option<String> {
   
   // let collection_of_values:Vec<String> = Vec::new();
    let st = obj.as_object();
    if let Some(hashmap) = st {
        for (key, value) in hashmap {
            if key == element { //TODO check if the value is an array and take the array as response
                println!("the key {:?} result: {:?}",key, value);
                if let Some(val) = value.as_str(){
                    return Some(val.to_string());
                }
             
               // collection_of_values.add
            //    for i in &value.as_array(){
            //     for x in i.into_iter(){
            //         println!("THE result wanted:{}", x);
            //          return Some(x.to_string());
            //     }
            //    }
            }
            println!("keyy {}, value {}", key, value);
            if value.is_object() {
                println!("Isss object");
            }
            read_json_func(value,element);
        }
    }
    return None;
}

pub async fn send_req(path: String, base: &String, element: &String) -> Vec<String> {
    let mut serv = "".to_string();
    let mut collection_of_values:Vec<String> = Vec::new();
    let base_url = Url::parse(&base.to_string()).expect("hardcoded URL is known to be valid");
    let joined = base_url.join(&path);
    match joined {
        Ok(url) => {
            println!("URL {}", url);
            let request = Client::new();
            let response = request.get(url)
              .bearer_auth("eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJwb3BAZ21haWwuY29tIiwiaWF0IjoxNjY3NDgwMzEwLCJleHAiOjE2Njc1NjY3MTB9.gG00kvavn4Pq1ohFAJw9wwQAt4k4SP0IWAfDYB9Mn_ZqQfcoZ9wVMsv1BDrYDFtBTkwjEJDlooZB8yPsc3T-bA")
             .send()
             .await
             .expect("failed to get response")
             .text()
             .await
             .expect("failed to get payload");
            let mut object: Value = serde_json::from_str(&response).unwrap();
            for i in object.as_array() {
                for x in i.into_iter() {
                    println!("Printed object {:?}", x);
                    collection_of_values.push(read_json_func(&x, element).unwrap_or_default());
                }
            }
        }

        
        Err(_) => println!("error"),
    }
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
