use crate::{path::Operation, QuePay};
use serde_json::Value;

use super::http_client::RequestParameter;


pub fn create_payload_for_get(
    //check if there is an example
    //if query param and path param can be references
    swagger: &Value,
    op: &Operation,
    option_value: Option<String>,
) -> Vec<RequestParameter> {
    //TODO replace this with a model similar to the one in POST requests
    let mut params_vec = vec![];
    for param_ref in op.params().iter() {
        let parameter = param_ref.inner(&Value::Null);
        let in_var = parameter.param_in;
        let param_name = parameter.name.to_string();

        match in_var.as_str() {
            "path" => {
                let mut option_example_value = None;
                if let Some(value) = parameter.examples {
                    if let Some((_ex, val)) = value.into_iter().next(){
                        option_example_value = Some(val.value.to_string());
                    }
                }
                if let Some(schema_ref) = parameter.schema {
                    dbg!(&schema_ref);
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
                        if let Some((_ex, val)) = values.into_iter().next() {
                            final_value = val.value.to_string();
                            
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
