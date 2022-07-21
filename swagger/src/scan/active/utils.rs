use crate::{path::Operation, ActiveScan, QuePay};
use serde;
use serde_json::Value;

use super::http_client::RequestParameter;
use crate::OAS3_1;
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
    swagger: &Value,
    op: &Operation,
    value: String,
) -> Vec<RequestParameter> {
    let mut params_vec = vec![];
    for i in op.params().iter_mut() {
        let parameter = i.inner(&Value::Null);
        let in_var = parameter.param_in.to_string();
        let param_name = parameter.name.to_string();
        let slice = &param_name[..];

        match in_var.as_str() {
            "path" => {
                if let Some(schema_ref) = parameter.schema {
                    if let Some(schema_type) = schema_ref.inner(swagger).schema_type {
                        // let val_to_path:String;
                        match schema_type.as_str() {
                            "string" => {
                                let val_to_path = "randString";
                                params_vec.push(RequestParameter {
                                    name: param_name,
                                    value: (&val_to_path).to_string(),
                                    dm: QuePay::Path,
                                });
                            }
                            "integer" => {
                                let val_to_path = "1";
                                params_vec.push(RequestParameter {
                                    name: param_name,
                                    value: (&val_to_path).to_string(),
                                    dm: QuePay::Path,
                                });
                            }
                            _ => (),
                        };
                    }
                }
            }
            "query" => params_vec.push(RequestParameter {
                name: slice.to_string(),
                dm: QuePay::Query,
                value: value.to_string(),
            }),

            _ => (),
        };
    }
    params_vec
}
