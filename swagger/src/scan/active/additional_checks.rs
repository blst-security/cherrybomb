use crate::active::utils::{recursive_func_to_find_param, send_req};

///use super::utils::create_payload_for_get;
use super::*;
use colored::*;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        //let  vec_param_values: Vec<RequestParameter> = Vec::new();
        let mut vec_param: Vec<String> = Vec::new();
        let server = &self.oas.servers();
        let mut uuid_hash: HashMap<String, Vec<String>> = HashMap::new();
        for (path, item) in &self.oas.get_paths() {
            let mut flag = false;
            for (_m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                for i in op.params() {
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == *"path".to_string()
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
                                == "array"
                            {
                                let schema = i.schema.unwrap();

                                //if array in response
                                let val = schema.inner(&self.oas_value).items.unwrap_or_default();

                                let _var_name: Vec<String> = val
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
                                    &"id".to_string(),
                                );
                                let set: HashSet<_> = vec_param.drain(..).collect(); // dedup
                                vec_param.extend(set.into_iter());
                                for value in &vec_param {
                                    let mut vec_of_values =
                                        send_req(path.to_string(), value, auth, &server.clone())
                                            .await;
                                    if let Some(v) = uuid_hash.get_mut(value) {
                                        v.append(&mut vec_of_values);
                                    } else {
                                        uuid_hash.insert(value.clone(), vec_of_values.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        uuid_hash.retain(|_, v| !v.is_empty()); // remove all pair with 0 length
        let mut vec_of_keys = Vec::new(); // get all the key in a vec
        for key in uuid_hash.keys() {
            vec_of_keys.push(key.clone());
        }
        //   println!("THIS IS THE FINAL HASHMAP : {:?}", UUID_HASH);
        for (path, item) in &self.oas.get_paths() {
            for (_m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                let mut vec_params: Vec<RequestParameter> = Vec::new();
                for i in op.params() {
                    //TODO Check if there is only one param
                    let type_param = match i
                        .inner(&self.oas_value)
                        .param_in
                        .to_lowercase()
                        .to_owned()
                        .as_str()
                    {
                        "path" => QuePay::Path,
                        "query" => QuePay::Query,
                         _ => QuePay::None
                        
                    };
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
                        if let Some(value_to_send) = &uuid_hash.get(&elem_to_search) {
                            vec_params.push(RequestParameter {
                                // TODO check if others values are ok
                                name: param_name.to_string(),
                                value: value_to_send[0].to_string(),
                                dm: type_param,
                            });
                        }

                        //sending the request

                        let req = AttackRequest::builder()
                            .uri(server, path)
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
        ret_val
    }
}
