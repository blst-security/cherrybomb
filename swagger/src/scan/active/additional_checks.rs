use std::vec;

use super::utils::{create_payload, recursive_func_to_find_param};
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


impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_method_permissions_active(&self, auth: &Authorization) -> CheckRetVal {
        let mut  h: Vec<MHeader> = vec![MHeader::from("content-type", "application/json")];

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
                if method.eq(&Method::GET) || method.eq(&Method::DELETE){
                    h.remove(0);
                }

                let req = AttackRequest::builder()
                    .servers(self.oas.servers(), true)
                    .path(path)
                    .parameters(vec_param.clone())
                    .auth(auth.clone())
                    .method(method)
                    .headers(h.clone())
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
                h.push(MHeader::from("content-type", "application/json"));
            }
        }
        ret_val
    }

    pub async fn check_method_encoding(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();

        for oas_map in self.payloads.iter() {
            for (_json_path, _schema) in &oas_map.payload.map {
                for (m, op) in oas_map
                    .path
                    .path_item
                    .get_ops()
                    .iter()
                    .filter(|(m, _)| m == &Method::POST)
                {
                    if let Some(value_encod) = op.request_body.clone() {
                        let encoding = value_encod.inner(&self.oas_value).content;
                        let encoding = LIST_CONTENT_TYPE
                            .iter()
                            .filter_map(|t| {
                                if !encoding.contains_key(*t) {
                                    Some(*t)
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<&str>>();

                        for i in encoding {
                            let h = MHeader {
                                name: "Content-type".to_string(),
                                value: i.to_string(),
                            };
                            let vec_param =
                                create_payload(&self.oas_value, op, &self.path_params, Some("".to_string()));
                            let req = AttackRequest::builder()
                                .servers(self.oas.servers(), true)
                                .method(*m)
                                //  .payload(&oas_map.payload.payload.to_string())
                                //TODO! create function that translate json payload to XML and vice versa
                                .path(&oas_map.path.path)
                                .parameters(vec_param)
                                .auth(auth.clone())
                                .headers(vec![h])
                                .build();
                            let response_vector =
                                req.send_request_all_servers(self.verbosity > 0).await;
                            for response in response_vector {
                                ret_val.1.push(
                                    &req,
                                    &response,
                                    "Testing misconfiguration for encoding".to_string(),
                                );
                                ret_val.0.push((
                                    ResponseData {
                                        location: oas_map.path.path.clone(),
                                        alert_text: format!(
                                            "The endpoint: {} is not correctly configured for {} ",
                                            oas_map.path.path.clone(),
                                            i
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
        }
        ret_val
    }
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
        let h: Vec<MHeader> = vec![MHeader::from("content-type", "application/json")];

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
                for (m, op) in oas_map
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
                        let vec_params = create_payload(&self.oas_value, op, &self.path_params, Some("".to_string())); 
                         for (provider_item, provider_value) in &provider_hash {
                            provider_vec.push(provider_item.to_string());
                            let req = AttackRequest::builder()
                                .servers(self.oas.servers(), true)
                                .path(&oas_map.path.path)
                                .method(*m)
                                .headers(h.clone())
                                .parameters(vec_params.clone())
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
                    // if no param in body req exist in the default array
                    // so let's check if there is any good param in the query
                    else {

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
                                let req = AttackRequest::builder()
                                .servers(self.oas.servers(), true)
                                .path(&oas_map.path.path)
                                .method(*m)
                                .headers(h.clone())
                                .parameters(params_vec.clone())
                                .auth(auth.clone())
                                .payload(&oas_map.payload.payload.to_string(),
                                )
                                .build();
                                let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
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
            }
            (ret_val, provider_vec)

        }
    

    pub async fn check_parameter_pollution(
        &self,
        auth: &Authorization,
    ) -> (CheckRetVal, Vec<String>) {
        println!("POllution");
        let mut ret_val = CheckRetVal::default();
        let mut vec_polluted = vec!["blstparamtopollute".to_string()];
        //   let base_url = server.unwrap().get(0).unwrap().clone();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                let _text = path.to_string();
                if m == Method::GET {
                    let mut vec_param =
                        create_payload(&self.oas_value, op, &self.path_params, None);
                        for i in &vec_param{
                           &vec_polluted.push(i.value.clone());
                        }
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
                      //  dbg!(&response_vector);
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
                      //  break; // TODO what is this?
                    }
                }
            }
        }
        ret_val
    }
    pub async fn check_string_length_max(&self, auth: &Authorization) -> CheckRetVal {
        let h: Vec<MHeader> = vec![MHeader::from("content-type", "application/json")];

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
                            .headers(h.clone())
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
                                .push(&req, &response, "Testing Max length String".to_string());
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
    pub async fn check_min_max(&self, auth: &Authorization) -> CheckRetVal {
        let h: Vec<MHeader> = vec![MHeader::from("content-type", "application/json")];

        let mut ret_val = CheckRetVal::default();
        for oas_map in self.payloads.iter() {
            for (json_path, schema) in &oas_map.payload.map {
                let test_vals = Vec::from([
                    schema.minimum.map(|min| ("minimum", min - 1.0)),
                    schema.maximum.map(|max| ("maximum", max + 1.0)),
                ]);
                // dbg!(&test_vals);
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
                            .headers(h.clone())
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
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let h: Vec<MHeader> = vec![MHeader::from("content-type", "application/json")];

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
         // println!("THIS IS THE FINAL HASHMAP : {:?}", UUID_HASH);
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
                        let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
                        for res in response_vector {
                            //logging
                            //logging request/response/description
                            ret_val
                                .1
                                .push(&req, &res, "Testing for Broken level authorization".to_string());
                            ret_val.0.push((
                                      ResponseData{
                                          location: path.clone(),
                                          alert_text: format!("The parameter {elem_to_search} seems to be vulnerable to BOLA, location: {path} ."),
                                          serverity: Level::High,
                                      },
                                  res.clone(),
                                  ));
                        }
                    }
                }
            }
        }
        ret_val
    }
    pub async fn check_broken_object_level_authorization(
        &self,
        auth: &Authorization,
    ) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param: Vec<RequestParameter> = Vec::new();
        let server = &self.oas.servers();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item
                .get_ops()
                .iter()
                .filter(|(m, _)| m != &Method::POST || m != &Method::PUT)
            {
                for i in op.params() {
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == *"path".to_string()
                    {
                        break;
                    }
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == *"query".to_string()
                    {
                        if i.inner(&self.oas_value)
                            .name
                            .to_lowercase()
                            .contains(&"id".to_string())
                        {
                            if let Some(types) = i
                                .inner(&self.oas_value)
                                .schema()
                                .inner(&self.oas_value)
                                .schema_type
                            {
                                let mut value_to_send = "2".to_string();
                                let mut var_int: i32 = 2;
                                if types == *"integer".to_string() {
                                    if let Some(val) = i.inner(&self.oas_value).examples {
                                        if let Some((_ex, val)) = val.into_iter().next() {
                                            value_to_send = val.value.to_string();
                                            var_int = value_to_send.parse::<i32>().unwrap();
                                        }
                                        for n in var_int - 1..var_int + 1 {
                                            println!("PATH {:?}", path);
                                            let param_to_send: RequestParameter =
                                                RequestParameter {
                                                    name: i.inner(&self.oas_value).name.to_string(),
                                                    value: n.to_string(),
                                                    dm: QuePay::Query,
                                                };
                                            vec_param.push(param_to_send);
                                            let req = AttackRequest::builder()
                                                .uri(server, path)
                                                .method(*m)
                                                .auth(auth.clone())
                                                .build();
                                                let response_vector =
                                                req.send_request_all_servers(self.verbosity > 0).await;
                                                for res in response_vector
                                            {
                                                //logging request/response/description
                                                ret_val.1.push(
                                                    &req,
                                                    &res,
                                                    "Testing for BOLA".to_string(),
                                                );
                                                ret_val.0.push((
                                                    ResponseData {
                                                        location: path.clone(),
                                                        alert_text: format!(
                                    "The endpoint {path} seems  to broken in context of authorization with parameter {var_int:?}."
                                ),
                                                        serverity: Level::Medium,
                                                    },
                                                    res.clone(),
                                                ));
                                            } 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ret_val
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

    pub async fn check_authentication_for_post(&self, _auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let h =vec![MHeader::from("content-type", "application/json")];
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
                            .headers(h.clone())
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




const LIST_CONTENT_TYPE: [&str; 2] = ["application/xml", "application/xml"];
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
