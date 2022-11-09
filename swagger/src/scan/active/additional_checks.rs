use crate::active::utils::{recursive_func_to_find_param, send_req};

///use super::utils::create_payload_for_get;
use super::*;
use colored::*;
use futures::TryFutureExt;
use reqwest::Client;
use reqwest::{self, Url};
use serde::ser::Error;
use serde_json::json;
use utils;
pub fn change_payload(orig: &Value, path: &[String], new_val: Value) -> Value {
    let mut change = &mut json!(null);
    let mut ret = orig.clone();
    for path_part in path.iter() {
        change = &mut ret[path_part];
    }
    *change = new_val;
    ret.clone()
}
impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param_values: Vec<RequestParameter> = Vec::new();
        let mut vec_param: Vec<String> = Vec::new();

        let server = &self.oas.servers();
        let mut UUID_HASH: HashMap<String, Vec<String>> = HashMap::new();
        for (path, item) in &self.oas.get_paths() {
            let mut flag = false;
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                for i in op.params() {
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == "path".to_string()
                    {
                        flag = true;
                        break;
                    }
                }
                if !flag {
                    // if no path param
                    let responses = op.responses();
                    let data_resp = responses.get(&"200".to_string());
                    if let Some(v) = data_resp {
                        let values = v
                            .inner(&self.oas_value)
                            .content
                            .unwrap_or_default()
                            .into_values();
                        for i in values {
                            if i.schema
                                .as_ref()
                                .unwrap()
                                .inner(&self.oas_value)
                                .schema_type
                                .unwrap_or_default()
                                .to_string()
                                == "array".to_string()
                            {
                                let schema = i.schema.unwrap();

                                //if array in response
                                let val = schema.inner(&self.oas_value).items.unwrap_or_default();

                                let var_name: Vec<String> = val
                                    .inner(&self.oas_value)
                                    .properties
                                    .unwrap()
                                    .keys()
                                    .cloned()
                                    .collect();
                                recursive_func_to_find_param(
                                    &self.oas_value,
                                    schema,
                                    &mut vec_param,
                                );
                                let set: HashSet<_> = vec_param.drain(..).collect(); // dedup
                                vec_param.extend(set.into_iter());
                                for value in &vec_param {
                                    let mut vec_of_values = send_req(
                                        path.to_string(),
                                        &"http://localhost:8888/".to_string(),
                                        &value,
                                        &auth,
                                        &server.clone(),
                                    )
                                    .await;
                                    if let Some(V) = UUID_HASH.get_mut(value) {
                                        V.append(&mut vec_of_values);
                                    } else {
                                        UUID_HASH.insert(value.clone(), vec_of_values.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        UUID_HASH.retain(|_, v| v.len() != 0); // remove all pair with 0 length
        let mut vec_of_keys = Vec::new(); // get all the key in a vec
        for key in UUID_HASH.keys() {
            vec_of_keys.push(key.clone());
        }
        println!("THIS IS THE FINAL HASHMAP : {:?}", UUID_HASH);
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                let mut vec_params: Vec<RequestParameter> = Vec::new();
                for i in op.params() {
                    //TODO Check if there is only one param
                    let mut type_param;
                    match &i.inner(&self.oas_value).param_in.to_lowercase() {
                        path => type_param = QuePay::Path,
                        query => type_param = QuePay::Query,
                    }
                    let param_name = &i.inner(&self.oas_value).name;
                    let mut flag = false;
                    let mut elem_to_search = "".to_string();
                    for i in &vec_param {
                        if param_name.to_lowercase() == i.to_lowercase() {
                            flag = true;
                            elem_to_search = i.to_string();
                        }
                    }
                    if flag {
                        let value_to_send = &UUID_HASH.get(&elem_to_search).unwrap()[0];
                        vec_params.push(RequestParameter {
                            // TODO check if others values are ok
                            name: param_name.to_string(),
                            value: value_to_send.to_string(),
                            dm: type_param,
                        });

                        //sending the request

                        let req = AttackRequest::builder()
                            .uri(&server, path)
                            .parameters(vec_params.clone())
                            .auth(auth.clone())
                            .method(Method::GET)
                            .headers(vec![])
                            .auth(auth.clone())
                            .build();
                        if let Ok(res) = req.send_request(self.verbosity > 0).await {
                            //logging
                            //logging request/response/description
                            ret_val
                                .1
                                .push(&req, &res, "Testing open-redirect".to_string());
                            ret_val.0.push((
                                      ResponseData{
                                          location: path.clone(),
                                          alert_text: format!("The parameter {} seems to be vulnerable to BOLA, location: {}  ",elem_to_search,path),
                                          serverity: Level::High,
                                      },
                                  res.clone(),
                                  ));
                        } else {
                            println!("{}", "REQUEST FAILED".red());
                        }
                    }
                }
            }
        }
        return ret_val;
    }
}
