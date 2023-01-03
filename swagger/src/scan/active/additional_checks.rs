use super::utils::create_payload;
///use super::utils::create_payload_for_get;
use super::*;
use serde_json::json;
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

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_for_ssrf(&self, auth: &Authorization) -> (CheckRetVal, Vec<String>) {
        println!("-------------------------GET SSRF-----------------------");

        let mut ret_val = CheckRetVal::default();
        let mut provider_vec = vec![];
        let provider_hash = HashMap::from([
            ("Amazon", "http://169.254.169.254/"),
            ("Google", "http://169.254.169.254/computeMetadata/v1/"),
            ("Digital", "http://169.254.169.254/metadata/v1.json"),
            ("Azure", "http://169.254.169.254/metadata/v1/maintenance"),
        ]);
 
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::GET {
                    let mut param_is_good_to_send = false;

                    for (provider_item, value_to_send) in &provider_hash {
                        let mut params_vec = vec![];
                        let payload_get_param = create_payload(
                            &self.oas_value,
                            op,
                            &self.path_params,
                            Some(value_to_send.to_string()),
                        );
                        for parameter_item in payload_get_param {
                            if parameter_item.dm == QuePay::Query && LIST_PARAM.contains(&parameter_item.name.as_str()) {
                                                         param_is_good_to_send = true;
                                                   } 
                            params_vec.push(parameter_item);

                        }

                        if param_is_good_to_send {
                            provider_vec.push(provider_item.to_string());
                            println!("SSRF GET: ----");
                            let req = AttackRequest::builder()
                                .servers(self.oas.servers(), true)
                                .path(path)
                                .parameters(params_vec.clone())
                                .auth(auth.clone())
                                .method(m)
                                .headers(vec![])
                                .auth(auth.clone())
                                .build();
                                let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
                                for response in response_vector {
                                    ret_val.1.push(&req, &response, "Testing SSRF".to_string());
                                    ret_val.0.push((
                                        ResponseData {
                                            location: path.to_string(),
                                            alert_text: format!(
                                                "The endpoint {} seems to be vulnerable to SSRF",
                                                path
                                            ),
                                            serverity: Level::Medium,
                                        },
                                        response,
                                    ));
                                }
                           
                        }
                    }
                }
            }
        }
        (ret_val, provider_vec)
    }

    pub async fn check_ssrf_post(&self, auth: &Authorization) -> (CheckRetVal, Vec<String>) {
        println!("-------------------------POST SSRF-----------------------");
        let mut ret_val = CheckRetVal::default();
        let mut provider_vec = vec![];
        let provider_hash = HashMap::from([
            ("Amazon", "http://169.254.169.254/"),
            ("Google", "http://169.254.169.254/computeMetadata/v1/"),
            ("Digital", "http://169.254.169.254/metadata/v1.json"),
            ("Azure", "http://169.254.169.254/metadata/v1/maintenance"),
        ]);
        for oas_map in self.payloads.iter() {
            for json_path in oas_map.payload.map.keys() {
                for (m, _) in oas_map
                    .path
                    .path_item
                    //.filter(|| path_item==p)
                    .get_ops()
                    .iter()
                    .filter(|(m, _)| m == &Method::POST)
                //947
                {
                    let param_to_test =
                        &json_path.last().unwrap_or(&"empty".to_string()).to_owned()[..];
                
                    if LIST_PARAM.contains(&param_to_test) {
                        for (provider_item, provider_value) in &provider_hash {
                            provider_vec.push(provider_item.to_string());
                            let req = AttackRequest::builder()
                                .servers(self.oas.servers(), true)
                                .path(&oas_map.path.path)
                                .method(*m)
                                .headers(vec![])
                                .parameters(vec![])
                                .auth(auth.clone())
                                .payload(
                                    &change_payload(
                                        &oas_map.payload.payload,
                                        json_path,
                                        json!(provider_value),
                                    )
                                    .to_string(),
                                )
                                .build();

                            print!("POST SSRF : ");
                            let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
                            for response in response_vector {
                                ret_val.1.push(&req, &response, "Testing SSRF".to_string());
                                ret_val.0.push((
                                    ResponseData {
                                        location: oas_map.path.path.to_string(),
                                        alert_text: format!(
                                            "The endpoint {} seems to be vulnerable to SSRF",
                                          &oas_map.path.path.clone()
                                        ),
                                        serverity: Level::Medium,
                                    },
                                    response,
                                ));
                            }
 
                        }
                    }
                }
            }
            }
            (ret_val, provider_vec)

        }
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
                        let vec_param = create_payload(
                            &self.oas_value,
                            op,
                            &self.path_params,
                            Some("".to_string()),
                        );
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
                                        "The {} for {json_path:?} is not enforced by the server",
                                        val.0, 
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
                let vec_param = create_payload(
                    &self.oas_value,
                    op,
                    &self.path_params,
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
                            ret_val.1.push(
                                &req,
                                &response,
                                "Checking for Open redirect".to_string(),
                            );
                            ret_val.0.push((
                                ResponseData {
                                    location: path.clone(),
                                    alert_text: format!(
                                        "The parameter {param_to_redirect} seems to be vulnerable to open-redirect, location: {path}" ),
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
                        let vec_param = create_payload(
                            &self.oas_value,
                            op,
                            &self.path_params,
                            Some("".to_string()),
                        );

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
                                        "The {max_len} length limit for {json_path:?} is not enforced by the server"
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
        println!("POllution");
        let mut ret_val = CheckRetVal::default();
        let vec_polluted = vec!["blstparamtopollute".to_string()];
        //   let base_url = server.unwrap().get(0).unwrap().clone();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                let _text = path.to_string();
                if m == Method::GET {
                    let mut vec_param =
                        create_payload(&self.oas_value, op, &self.path_params, None);
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
        (ret_val, vec_polluted)
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
                    serverity: Level::Medium,
                },
                response.clone(),
            ));
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

            let vec_param = create_payload(
                &self.oas_value,
                item.get_ops()[0].1,
                &self.path_params,
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
                    .push(&req, &response, "Testing method permission".to_string());
                ret_val.0.push((
                                ResponseData {
                                    location: path.to_string(),
                                    alert_text: format!("The endpoint seems to be not secure {:?}, with the method : {method} ", &path ),
                                    serverity: Level::High,
                                },
                                response,
                            ));
                }
            }
        }
        ret_val
    }

    pub async fn check_authentication_for_post(&self, _auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        for oas_map in self.payloads.iter() {
            //for (_json_path, _schema) in &oas_map.payload.map {
            for _schema in oas_map.payload.map.values() {
                for (m, op) in oas_map.path.path_item.get_ops().iter() {
                    let vec_param =
                        create_payload(&self.oas_value, op,&self.path_params, Some("".to_string()));
                    let url = &self.oas.servers();
                    if let Some(_value) = &op.security {
                        let req = AttackRequest::builder()
                            .servers(self.oas.servers(),true)
                            .path(&oas_map.path.path)
                            .method(*m)
                            .headers(vec![])
                            .parameters(vec_param.clone())
                            //.auth(auth.clone())
                            .payload(&oas_map.payload.payload.to_string())
                            .build();

                      
                            let response_vector =
                            req.send_request_all_servers(self.verbosity > 0).await;
                        for response in response_vector {
                            ret_val
                                .1
                                .push(&req, &response, "Testing without auth".to_string());
                            ret_val.0.push((
                                ResponseData {
                                    location: oas_map.path.path.to_string(),
                                    alert_text: format!("The endpoint seems to be not secure {:?}, with the method : {m} ", &oas_map.path.path),
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
    pub async fn check_authentication_for_get(&self, _auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let server = self.oas.servers();
        //   let base_url = server.unwrap().get(0).unwrap().clone();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::GET {
                    let vec_param =
                        create_payload(&self.oas_value, op,&self.path_params, Some("".to_string()));
                    let req = AttackRequest::builder()
                        .servers(self.oas.servers(), true)
                        .path(&path.clone())
                        .method(m)
                        .headers(vec![])
                        .parameters(vec_param.clone())
                        .build();
                        let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
                        for response in response_vector{
                        //logging request/response/description
                        ret_val
                            .1
                            .push(&req, &response, "Testing without auth".to_string());
                        // println!("Status Code : {:?}", res.status);
                        ret_val.0.push((
                            ResponseData{
                                location: path.to_string(),
                                alert_text: format!("The endpoint seems to be not secure {path:?}, with the method : {m}"),
                                serverity: Level::High,
                            },
                        response,
                    ));
                    } 
                }
                }
            }
            ret_val
        }
        
    }


const LIST_METHOD: [Method; 3] = [Method::GET, Method::POST, Method::PUT];
const LIST_PARAM: [&str; 86] = [
    "photoUrls",
    "page",
    "url",
    "ret",
    "r2",
    "img",
    "u",
    "return",
    "r",
    "URL",
    "next",
    "redirect",
    "redirectBack",
    "AuthState",
    "referer",
    "redir",
    "l",
    "aspxerrorpath",
    "image_path",
    "ActionCodeURL",
    "return_url",
    "link",
    "q",
    "location",
    "ReturnUrl",
    "uri",
    "referrer",
    "returnUrl",
    "forward",
    "file",
    "rb",
    "end_display",
    "urlact",
    "photoUrls",
    "from",
    "goto",
    "path",
    "redirect_url",
    "old",
    "pathlocation",
    "successTarget",
    "returnURL",
    "urlsito",
    "newurl",
    "Url",
    "back",
    "retour",
    "odkazujuca_linka",
    "r_link",
    "cur_url",
    "H_name",
    "ref",
    "topic",
    "resource",
    "returnTo",
    "home",
    "node",
    "sUrl",
    "href",
    "linkurl",
    "returnto",
    "redirecturl",
    "SL",
    "st",
    "errorUrl",
    "media",
    "destination",
    "targeturl",
    "return_to",
    "cancel_url",
    "doc",
    "GO",
    "ReturnTo",
    "anything",
    "FileName",
    "logoutRedirectURL",
    "list",
    "startUrl",
    "service",
    "redirect_to",
    "end_url",
    "_next",
    "noSuchEntryRedirect",
    "context",
    "returnurl",
    "ref_url",
];
