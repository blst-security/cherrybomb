use super::utils::create_payload;
///use super::utils::create_payload_for_get;
use super::*;
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
/*pub async fn func_test(&self, _auth: &Authorization) -> CheckRetVal {
let values_path = self.path_params.clone();
let ret_val = CheckRetVal::default();
for (_path, item) in &self.oas.get_paths() {
    for (_m, op) in item.get_ops().iter() {
        self.oas.servers();
        // create_payload(&self.oas_value, op);

        //dbg!(create_payload(&self.oas_value, op, &values_path, None));
       }
       */

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
    pub async fn check_min_max(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        for oas_map in self.payloads.iter() {
            for (json_path, schema) in &oas_map.payload.map {
                let test_vals = Vec::from([
                    schema.minimum.map(|min| ("minimum", min - 1.0)),
                    schema.maximum.map(|max| ("maximum", max + 1.0)),
                ]);
                for val in test_vals.into_iter().flatten() {
                    for (m, op) in oas_map
                        .path
                        .path_item
                        .get_ops()
                        .iter()
                        .filter(|(m, _)| m == &Method::POST)
                    {
                        let vec_param =
                            create_payload_for_get(&self.oas_value, op, Some("".to_string()));
                        let req = AttackRequest::builder()
                            .servers(self.oas.servers(), true)
                            .path(&oas_map.path.path)
                            .method(*m)
                            .headers(vec![])
                            .parameters(vec_param.clone())
                            .auth(auth.clone())
                            .payload(
                                &change_payload(&oas_map.payload.payload, json_path, json!(val.1))
                                    .to_string(),
                            )
                            .build();
                        let response_vector =
                            req.send_request_all_servers(self.verbosity > 0).await;
                        for response in response_vector {
                            ret_val
                                .1
                                .push(&req, &response, "Testing  /max values".to_string());
                            ret_val.0.push((
                                ResponseData {
                                    location: oas_map.path.path.clone(),
                                    alert_text: format!(
                                        "The {} for {:?} is not enforced by the server",
                                        val.0, json_path
                                    ),
                                    serverity: Level::Low,
                                },
                                response,
                            ));
                        }
                    }
                }
            }
        }
        ret_val
    }

    pub async fn check_open_redirect(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                let vec_param = create_payload_for_get(
                    &self.oas_value,
                    op,
                    Some("http://www.google.com".to_string()),
                );
                for param_item in &vec_param {
                    // dbg!(&param_item);
                    if param_item.dm == QuePay::Query
                        && LIST_PARAM.contains(&param_item.name.as_str())
                    {
                        let param_to_redirect = param_item.name.to_owned();
                        let req = AttackRequest::builder()
                            .servers(self.oas.servers(), true)
                            .path(path)
                            .parameters(vec_param.clone())
                            .auth(auth.clone())
                            .method(*m)
                            .headers(vec![])
                            .auth(auth.clone())
                            .build();
                        let response_vector =
                            req.send_request_all_servers(self.verbosity > 0).await;
                        for response in response_vector {
                            ret_val
                                .1
                                .push(&req, &response, "Testing  /max values".to_string());
                            ret_val.0.push((
                                ResponseData {
                                    location: path.clone(),
                                    alert_text: format!(
                                        "The parameter {} seems to be vulnerable to open-redirect, location: {}  "
                                        , param_to_redirect, path),
                                    serverity: Level::Medium,
                                },
                                response,
                            ));
                        }
                        break; // TODO what is this?
                    }
                }
            }
        }
        ret_val
    }

    pub async fn check_string_length_max(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        for oas_map in self.payloads.iter() {
            for (json_path, schema) in &oas_map.payload.map {
                if let Some(max_len) = schema.max_length {
                    let new_string = iter::repeat(['B', 'L', 'S', 'T'])
                        .flatten()
                        .take(max_len.try_into().unwrap())
                        .collect::<String>();
                    for (m, op) in oas_map
                        .path
                        .path_item
                        .get_ops()
                        .iter()
                        .filter(|(m, _)| m == &Method::POST)
                    {
                        let vec_param =
                            create_payload_for_get(&self.oas_value, op, Some("".to_string()));

                        let url = self.oas.servers();

                        let req = AttackRequest::builder()
                            .servers(url, true)
                            .path(&oas_map.path.path)
                            .method(*m)
                            .headers(vec![])
                            .parameters(vec_param.clone())
                            .auth(auth.clone())
                            .headers(Vec::from([MHeader {
                                name: "Content-Type".to_string(),
                                value: "application/json".to_string(),
                            }]))
                            .payload(
                                &change_payload(
                                    &oas_map.payload.payload,
                                    json_path,
                                    json!(new_string),
                                )
                                .to_string(),
                            )
                            .build();
                        let response_vector =
                            req.send_request_all_servers(self.verbosity > 0).await;
                        for response in response_vector {
                            ret_val
                                .1
                                .push(&req, &response, "Testing  /max values".to_string());
                            ret_val.0.push((
                                ResponseData {
                                    location: oas_map.path.path.clone(),
                                    alert_text: format!(
                                        "The {} length limit for {:?} is not enforced by the server",
                                        max_len,
                                        json_path
                                    ),
                                    serverity: Level::Low,
                                },
                                response,
                            ));
                        }
                    }
                }
            }
        }
        ret_val
    }

    pub async fn check_parameter_pollution(
        &self,
        auth: &Authorization,
    ) -> (CheckRetVal, Vec<String>) {
        let mut ret_val = CheckRetVal::default();
        let vec_polluted = vec!["blstparamtopollute".to_string()];
        //   let base_url = server.unwrap().get(0).unwrap().clone();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                let _text = path.to_string();
                if m == Method::GET {
                    let mut vec_param = create_payload_for_get(&self.oas_value, op, None);
                    let indices = vec_param
                        .iter()
                        .enumerate()
                        .filter(|(_, x)| x.dm == QuePay::Query)
                        .map(|(index, _)| index)
                        .collect::<Vec<_>>();
                    for i in indices {
                        let param_query_pollute = vec_param.get(i).unwrap().clone();
                        vec_param.push(param_query_pollute);
                        let req = AttackRequest::builder()
                            .servers(self.oas.servers(), true)
                            .path(path)
                            .auth(auth.clone())
                            .parameters(vec_param.clone())
                            .method(m)
                            .headers(vec![])
                            .auth(auth.clone())
                            .build();
                        let response_vector =
                            req.send_request_all_servers(self.verbosity > 0).await;
                        for response in response_vector {
                            ret_val.1.push(
                                &req,
                                &response,
                                "Testing get parameter pollution ".to_string(),
                            );
                            ret_val.0.push((
                                ResponseData {
                                    location: path.clone(),
                                    alert_text: format!(
                                        "The {} parameter in the {} endpoint seems to be vulnerable to parameter pollution"
                                        , vec_param.last().unwrap().name, path),
                                    serverity: Level::Medium,
                                },
                                response,
                            ));
                        }
                        vec_param.remove(vec_param.len() - 1);
                    }
                }
            }
        }

        pub async fn check_ssl(&self, auth: &Authorization) -> CheckRetVal {
            let mut ret_val = CheckRetVal::default();
            let req = AttackRequest::builder()
                .servers(self.oas.servers(), false)
                .path("")
                .auth(auth.clone())
                .parameters(vec![])
                .method(Method::GET)
                .headers(vec![])
                .auth(auth.clone())
                .build();
            let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
            for (response, server) in response_vector.iter().zip(req.servers.iter()) {
                ret_val.1.push(&req, response, "Testing SSL".to_string());
                ret_val.0.push((
                    ResponseData {
                        location: server.base_url.clone(),
                        alert_text: format!(
                            "The server does not seem to be using SSL, status code: {}",
                            response.status
                        ),
                        serverity: Level::Low,
                    },
                    response.clone(),
                ));
            }
            ret_val
        }

        pub async fn check_authentication(&self, _auth: &Authorization) -> CheckRetVal {
            let mut ret_val = CheckRetVal::default();
            for oas_map in self.payloads.iter() {
                for _schema in oas_map.payload.map.values() {
                    for (m, op) in oas_map.path.path_item.get_ops().iter() {
                        let vec_param =
                            create_payload_for_get(&self.oas_value, op, Some("".to_string()));
                        if let Some(_value) = &op.security {
                            let req: AttackRequest = if m == &Method::POST {
                                AttackRequest::builder() //TODO THIS IF STATEMENT CAN BE MOVED INTO THE BUILDER
                                    .servers(self.oas.servers(), true)
                                    .path(&oas_map.path.path)
                                    .method(*m)
                                    .headers(vec![])
                                    .parameters(vec_param.clone())
                                    //.auth(auth.clone())
                                    .payload(&oas_map.payload.payload.to_string())
                                    .build()
                            } else {
                                AttackRequest::builder()
                                    .servers(self.oas.servers(), true)
                                    .path(&oas_map.path.path)
                                    .method(*m)
                                    .headers(vec![])
                                    .parameters(vec_param.clone())
                                    .build()
                            };
                            let response_vector =
                                req.send_request_all_servers(self.verbosity > 0).await;
                            for response in response_vector {
                                ret_val.1.push(
                                    &req,
                                    &response,
                                    "Testing authentication".to_string(),
                                );
                                ret_val.0.push((
                                    ResponseData {
                                        location: oas_map.path.path.clone(),
                                        alert_text: format!(
                                        "The {} endpoint does not seem to require authentication",
                                        oas_map.path.path
                                    ),
                                        serverity: Level::High,
                                    },
                                    response,
                                ));
                            }
                        }
                    }
                }
            }
            ret_val
        }

        pub async fn check_method_permissions_active(&self, auth: &Authorization) -> CheckRetVal {
            let mut ret_val = CheckRetVal::default();
            for (path, item) in &self.oas.get_paths() {
                let current_method_set = item
                    .get_ops()
                    .iter()
                    .map(|(m, _)| m)
                    .cloned()
                    .collect::<HashSet<_>>();

                let vec_param = create_payload_for_get(
                    &self.oas_value,
                    item.get_ops()[0].1,
                    Some("".to_string()),
                );

                let all_method_set = HashSet::from(LIST_METHOD);
                for method in all_method_set.difference(&current_method_set).cloned() {
                    let req = AttackRequest::builder()
                        .servers(self.oas.servers(), true)
                        .path(path)
                        .parameters(vec_param.clone())
                        .auth(auth.clone())
                        .method(method)
                        .headers(vec![])
                        .build();
                    let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
                    for response in response_vector {
                        ret_val
                            .1
                            .push(&req, &response, "Testing method permissions".to_string());
                        ret_val.0.push((
                            ResponseData {
                                location: path.clone(),
                                alert_text: format!(
                                    "The {} endpoint accepts {:?} although its not documented to",
                                    path, method
                                ),
                                serverity: Level::High,
                            },
                            response,
                        ));
                    }
                }
            }
            ret_val
        }
    }
}
