use crate::{path::Operation, QuePay};
use serde_json::Value;

use super::http_client::RequestParameter;

// use super::*;
// pub fn get_path_urls(path: &PathItem, servers: Option<Vec<Server>>) -> Vec<(Method, String)> {
//     let mut urls = vec![];
//     let methods: Vec<Method> = path.get_ops().iter().map(|(m, _)| m).cloned().collect();
//     for (m, op) in path.get_ops() {
//         if let Some(servers) = &op.servers {
//             urls.extend(
//                 servers
//                     .iter()
//                     .map(|s| (m, s.url.clone()))
//                     .collect::<Vec<(Method, String)>>(),
//             );
//         }
//     }
//     if urls.is_empty() {
//         if let Some(servers) = servers {
//             for m in methods {
//                 urls.extend(servers.iter().map(|s| (m, s.url.clone())));
//             }
//         }
//     }
//     urls
// }
pub fn create_string(num: i64) -> String {
    let mut str = String::from("");
    for n in 0..num + 1 {
        println!("{:?}", n);
        str.push_str("a");
    }
    str
}
pub fn create_payload_for_get(
    //check if there is an exmaple
    //if query param and path param can be references
    swagger: &Value,
    op: &Operation,
    option_value: Option<String>,
) -> Vec<RequestParameter> {
    let mut params_vec = vec![];
    for i in op.params().iter_mut() {
        let parameter = i.inner(&Value::Null);
        let in_var = parameter.param_in;
        let param_name = parameter.name.to_string();

        // let slice = &param_name[..];

        match in_var.as_str() {
            "path" => {
                let mut option_example_value = None;
                if let Some(value) = parameter.examples {
                    for (_ex, val) in value {
                        option_example_value = Some(val.value.to_string());
                        break;
                    }
                }
                if let Some(schema_ref) = parameter.schema {
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
                    }
                }
            }
            "query" => {
                let mut final_value = "blstpollute".to_string();
                if option_value.as_ref().is_none() {
                    // let mut example_value = "randomString".to_string();
                    //let mut  option_example_value= None  ;
                    if let Some(values) = parameter.examples {
                        for (_ex, val) in values {
                            final_value = val.value.to_string();
                            break;
                        }
                    }
                } else {
                    final_value = option_value.as_ref().unwrap().to_string();
                }
                // if let Some(ref v)= option_value{
                //     final_value= v.to_string();
                // }
                params_vec.push(RequestParameter {
                    name: param_name,
                    dm: QuePay::Query,
                    value: final_value,
                });
            }
            _ => (),
        };
    }
    params_vec
}
