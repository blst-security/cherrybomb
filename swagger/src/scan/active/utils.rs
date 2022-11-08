use std::collections::HashMap;

use super::http_client::RequestParameter;
use crate::{path::Operation, QuePay, refs::{ResponseRef, SchemaRef}};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn recursive_func_to_find(swagger: &Value, schema: SchemaRef, vec_of_param:  &mut Vec<String>)
-> Vec<String> {
    let properti_option = schema.inner(swagger).items;
    println!("{:?}",&properti_option);
    if let Some(schemaB) = properti_option{
   
    let propertie = schemaB.inner(swagger).properties.unwrap_or_default();
    
    for (key, value) in propertie {
        println!("################\n");
        let inner_ref = value.inner(swagger).items;
      
        if key.contains("id") && inner_ref.is_none(){
            vec_of_param.push(key);
        }
        else if value.inner(swagger).properties.is_some(){


            recursive_func_to_find(swagger, value, vec_of_param);
        }   
    
    }
    }
    let propertie = schema.inner(swagger).properties.unwrap_or_default(); //if let failed 
    //meanning that the schemaref is none so we need build it 
    
    for (key, value) in propertie {
        println!("################\n");
        let inner_ref = value.inner(swagger).items;
        println!("key2: {:?} value2 :{:?}", key, value );
        if key.contains("id") && inner_ref.is_none(){
            println!("this is the key {:?}", key);
            vec_of_param.push(key);
        }
        else if value.inner(swagger).properties.is_some(){
            recursive_func_to_find(swagger, value, vec_of_param);
        }   
    
    }
    vec_of_param.to_vec()

 }




pub fn find_id_param(
    swagger: &Value,
    data_resp:&ResponseRef) -> Vec<String> {
    let vec_of_params:Vec<String> = Vec::new();

    let values = data_resp
    .inner(swagger)
    .content
    .unwrap_or_default()
    .into_values();
for i in values {
     if i.schema
        .as_ref()
        .unwrap()
        .inner(swagger)
        .schema_type
        .unwrap_or_default()
        .to_string()
        == "array".to_string()

    {
        //if array in response
        let val = i
            .schema
            .unwrap()
            .inner(swagger)
            .items
            .unwrap_or_default();
       // println!("THIS IS VAL : {:?}", val);
        let var_name: Vec<String> = val
                                    .inner(swagger)
                                    .properties
                                    .unwrap()
                                    .keys()
                                    .cloned()
                                    .collect();
        println!("This is the var_name vec {:?}", var_name);
        let elem = val.inner(swagger).properties.unwrap();
        for (keys, value) in elem {
           // println!("KEY : {:?} , value : {:?}", keys, value);
            let refr  = value.inner(swagger).properties.unwrap_or_default();
            println!("key is {:?} , this is the ref  {:?}", keys,refr);
    }
   
    
    }
}
vec_of_params
    }








pub fn read_json_func(obj: &Value, element: &String) -> Option<String> {
   let mut ret= None;
   
   // let collection_of_values:Vec<String> = Vec::new();
    let st = obj.as_object();
    println!("1");
    if let Some(hashmap) = st {
        println!("2");
        for (key, value) in hashmap {
            println!("3");
            println!("key: {}",key);
            if key == element { //TODO check if the value is an array and take the array as response
                println!("In the recusice function the key from the json {:?} and the param name: {:?} finally the value : {}",key, element, value);
               
                if let Some(val) = value.as_str(){
                    println!("\nFROM THE RECURSIVE FUNC is string  : {} ", val.to_string());
                    return Some(val.to_string());
                }
                if let Some(val) = value.as_u64(){
                    println!("\nFROM THE RECURSIVE FUNC is int: {} ", val);
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
         //   println!("keyy {}, value {}", key, value);
          if ret.is_none(){
          ret =  read_json_func(value,element);
          }
        }
    }
    return ret;
}

pub async fn send_req(path: String, base: &String, element: &String) -> Vec<String> {
    println!("#############################");
    let mut serv = "".to_string();
    let mut collection_of_values:Vec<String> = Vec::new();
    let base_url = Url::parse(&base.to_string()).expect("hardcoded URL is known to be valid");
    let joined = base_url.join(&path);
    match joined {
        Ok(url) => {
         //   println!("URL {}", url);
            let request = Client::new();
            let response = request.get(url)
             .bearer_auth("eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJwb3BAZ21haWwuY29tIiwiaWF0IjoxNjY3OTI0NTk5LCJleHAiOjE2NjgwMTA5OTl9.KGw_hh3mGXTsdbw0_O51SUdYHfe4hSNaUCRXD0fKlG6OrAwv1gVpj1_cnR7xyBm2iTRr-fPHib6UnZo-Zw7jEA")
             .send()
             .await
             .expect("failed to get response")
             .text()
             .await
             .expect("failed to get payload");
            let mut object: Value = serde_json::from_str(&response).unwrap();
            for i in object.as_array() { // take jsonresponse as array 
                for x in i.into_iter() {
                     println!("Printed object {:?}", x);
                    let elem  = read_json_func(&x, element); // check the value fo the key
                    println!("The elem : {:?} ", elem);
                    println!("-------------------");
                    if let Some(val) = elem {
                        println!("key : {:?}, Value : {:?} ", element, val);
                        println!("-------------------");
                        collection_of_values.push(val);
                    }
                  
                }
            }
        }

        
        Err(_) => println!("error"),
    }
    println!("--------Collections of values before send the main function: {:?}------", collection_of_values);
    println!("##################################");
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
