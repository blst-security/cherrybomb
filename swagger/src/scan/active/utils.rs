use super::http_client::RequestParameter;
use crate::{path::Operation, QuePay};
use serde_json::Value;

/// This function is used to create a payload for a GET request parameters
// TODO change this t be created at parse instead of on demand
pub fn create_payload_for_get(
    swagger: &Value,
    op: &Operation,
    test_value: Option<String>,
) -> Vec<RequestParameter> {
    let mut params_vec = vec![];
    for i in op.params().iter_mut() {
        let parameter = i.inner(swagger);
        let in_var = parameter.param_in;
        let param_name = parameter.name.to_string();
        match in_var.as_str() {
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
                    }
                }
            }
            "query" => {
                //todo support type
                let mut final_value = "blstpollute".to_string();
                if test_value.as_ref().is_none() {
                    // let mut example_value = "randomString".to_string();
                    //let mut  option_example_value= None  ;
                    if let Some(values) = parameter.examples {
                        if let Some((_ex, val)) = values.into_iter().next() {
                            final_value = val.value.to_string();
                        }
                    }
                } else {
                    final_value = test_value.as_ref().unwrap().to_string();
                }
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
