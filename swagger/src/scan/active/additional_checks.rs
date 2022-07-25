use super::{utils::create_payload_for_get, utils::create_string, *};
use serde_json::json;
// &use mapper::digest::Method&::POST&;
use colored::*;
const LIST_METHOD: [Method; 3] = [Method::GET, Method::POST, Method::PUT];
const LIST_CONTENT_TYPE: [&str; 2] = ["application/xml", "application/xml"];
const LIST_PARAM: [&str; 85] = [
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
                    schema.minimum.map(|min| ("minimum", min - 1)),
                    schema.maximum.map(|max| ("maximum", max + 1)),
                ]);
                for val in test_vals.into_iter().flatten() {
                    //
                    //println!("popopopopopopo");

                    // .filter_map(|x| x){
                    for (m, _) in oas_map
                        .path
                        .path_item
                        .get_ops()
                        .iter()
                        .filter(|(m, _)| m == &Method::POST)
                    {
                        let url;
                        if let Some(servers) = &self.oas.servers() {
                            if let Some(s) = servers.first() {
                                url = s.url.clone();
                            } else {
                                continue;
                            };
                        } else {
                            continue;
                        };
                        let req = AttackRequest::builder()
                            .uri(&url, &oas_map.path.path)
                            .method(*m)
                            .headers(vec![])
                            .parameters(vec![])
                            .auth(auth.clone())
                            .payload(
                                &change_payload(&oas_map.payload.payload, json_path, json!(val.1))
                                    .to_string(),
                            )
                            .build();
                        //    dbg!(&req);
                        print!("Min mAx : ");

                        if let Ok(res) = req.send_request(true).await {
                            //logging request/response/description
                            ret_val
                                .1
                                .push(&req, &res, "Testing min/max values".to_string());
                            ret_val.0.push((
                                ResponseData {
                                    location: oas_map.path.path.clone(),
                                    alert_text: format!(
                                        "The {} for {} is not enforced by the server",
                                        val.0,
                                        json_path[json_path.len() - 1]
                                    ),
                                },
                                res.clone(),
                            ));
                            println!(
                                "{}:{}",
                                "Status".green().bold(),
                                res.status.to_string().magenta()
                            );
                        } else {
                            println!("REQUEST FAILED");
                        }
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
                if let Some(int_max) = schema.max_length {
                    let new_string = create_string(int_max).clone();

                    let test_vals = Vec::from([(schema.max_length, &new_string)]);
                    for val in test_vals {
                        // .into_iter()
                        // .flatten(){
                        for (m, _) in oas_map
                            .path
                            .path_item
                            .get_ops()
                            .iter()
                            .filter(|(m, _)| m == &Method::POST)
                        {
                            let url;
                            if let Some(servers) = &self.oas.servers() {
                                if let Some(s) = servers.first() {
                                    url = s.url.clone();
                                } else {
                                    continue;
                                };
                            } else {
                                continue;
                            };
                            let req = AttackRequest::builder()
                                .uri(&url, &oas_map.path.path)
                                .method(*m)
                                .headers(vec![])
                                .parameters(vec![])
                                .auth(auth.clone())
                                .payload(
                                    &change_payload(
                                        &oas_map.payload.payload,
                                        json_path,
                                        json!(val.1),
                                    )
                                    .to_string(),
                                )
                                .build();

                            if let Ok(res) = req.send_request(true).await {
                                //logging request/response/description
                                ret_val
                                    .1
                                    .push(&req, &res, "Testing min/max length".to_string());
                                ret_val.0.push((
                                    ResponseData {
                                        location: oas_map.path.path.clone(),
                                        alert_text: format!(
                                            "The {:?} for {} is not enforced by the server",
                                            val.0,
                                            json_path[json_path.len() - 1]
                                        ),
                                    },
                                    res.clone(),
                                ));
                                println!(
                                    "{}:{}",
                                    "Status".green().bold(),
                                    res.status.to_string().magenta()
                                );
                            } else {
                                println!("REQUEST FAILED");
                            }
                        }
                    }
                }
            }
        }
        ret_val
    }

    pub async fn check_open_redirect(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let base_url = self.oas.servers().unwrap().get(0).unwrap().clone();

        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::GET {
                    let vec_param = create_payload_for_get(
                        &self.oas_value,
                        op,
                        Some("https://blst.security.com".to_string()),
                    );
                    for param_item in &vec_param {
                        if param_item.dm == QuePay::Query
                            && LIST_PARAM.contains(&param_item.name.as_str())
                        {
                            let param_to_redirect = param_item.name.to_owned();
                            let req = AttackRequest::builder()
                                .uri(&base_url.url, path)
                                .parameters(vec_param.clone())
                                .auth(auth.clone())
                                .method(m)
                                .headers(vec![])
                                .auth(auth.clone())
                                .build();
                            if let Ok(res) = req.send_request(true).await {
                                //logging
                                //logging request/response/description
                                ret_val
                                    .1
                                    .push(&req, &res, "Testing open-redirect".to_string());
                                ret_val.0.push((
                                ResponseData{
                                    location: path.clone(),
                                    alert_text: format!("The parameter {} seems to be vulerable to open-redirect, location: {}  ",param_to_redirect,path)
                                },
                            res.clone(),
                            ));
                            } else {
                                println!("REQUEST FAILED");
                            }
                            break;
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
        let server = self.oas.servers();
        //    let mut new_url:(String , String);
        let vec_polluted = vec!["blstparamtopollute".to_string()];
        let base_url = server.unwrap().get(0).unwrap().clone();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                let _text = path.to_string();
                //   println!("{:?}", text);
                if m == Method::GET {
                    let mut vec_param = create_payload_for_get(&self.oas_value, op, None);
                    //let param_to_add =vec_param.iter().find(|&x| x.dm == QuePay::Query ).collect;
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
                            .uri(&base_url.url, path)
                            .auth(auth.clone())
                            .parameters(vec_param.clone())
                            .method(m)
                            .headers(vec![])
                            .auth(auth.clone())
                            .build();
                        println!("Pollution ");
                        if let Ok(res) = req.send_request(true).await {
                            //logging request/response/description
                            ret_val.1.push(
                                &req,
                                &res,
                                " Testing get parameter pollution ".to_string(),
                            );
                            ret_val.0.push((
                                        ResponseData{
                                            location: path.clone(),
                                            alert_text: format!("The endpoint {} seems to be vulerable to parameter pollution on the {} parameter",path,vec_param.last().unwrap().name)
                                        },
                                        res.clone(),
                                    ));
                        } else {
                            println!("REQUEST FAILED");
                        }

                        vec_param.remove(vec_param.len() - 1);
                    }
                }
            }
        }
        (ret_val, vec_polluted)
    }
    pub async fn check_ssl(&self, auth: &Authorization) -> CheckRetVal {
        println!("SSL CHECK");
        let mut ret_val = CheckRetVal::default();
        if let Some(server_url) = self.oas.servers() {
            for i in server_url {
                // let format_url = create_http_url(i.url);
                let mut new_url = i.url;
                // let format_u  = &new_url[..5];
                //  &new_url[..5]="http";
                if new_url.contains("https") {
                    new_url.replace_range(0..5, "http");
                }

                let req = AttackRequest::builder()
                    .uri(&new_url, "")
                    .auth(auth.clone())
                    .build();
                println!("{}", req);
                if let Ok(res) = req.send_request(true).await {
                    //logging request/response/description
                    ret_val
                        .1
                        .push(&req, &res, "Testing uncrypted traffic".to_string());
                    ret_val.0.push((
                        ResponseData {
                            location: new_url.clone(),
                            alert_text: format!(
                                "The server: {} is not secure against https downgrade",
                                &new_url
                            ),
                        },
                        res.clone(),
                    ));
                } else {
                    println!("REQUEST FAILED");
                }
            }
        }

        ret_val
    }
    pub async fn check_method_permissions(&self, auth: &Authorization) -> CheckRetVal {
        //// reformat get with path parameter
        let mut ret_val = CheckRetVal::default();
        let mut vec_method: Vec<Method> = Vec::new();
        for (path, item) in &self.oas.get_paths() {
            for (m, _op) in item.get_ops() {
                vec_method.push(m);
            }

            let methodes = LIST_METHOD
                .iter()
                .filter_map(|s| {
                    if !vec_method.contains(s) {
                        Some(*s)
                    } else {
                        None
                    }
                })
                .collect::<Vec<Method>>();
            for i in methodes {
                println!("Method permissions:{:?}", i);
                let value_to_add =
                    Self::send_request_to_test(self, i, (&path).to_string(), auth).await;

                for i in value_to_add.0 {
                    ret_val.0.push(i);
                }
                ret_val.1 = value_to_add.1;
            }
        }
        ret_val
    }

    pub async fn send_request_to_test(
        swagger: &ActiveScan<T>,
        m: Method,
        p: String,
        auth: &Authorization,
    ) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let base_url = swagger.oas.servers().unwrap().get(0).unwrap().clone();

        let req = AttackRequest::builder()
            .uri(&base_url.url, &p)
            .auth(auth.clone())
            .method(m)
            .headers(vec![])
            .auth(auth.clone())
            .build();
        // println!("{}", req.path);
        if let Ok(res) = req.send_request(true).await {
            //logging
            //logging request/response/description
            ret_val
                .1
                .push(&req, &res, "Test method permission".to_string());
            ret_val.0.push((
                ResponseData {
                    location: p.clone(),
                    alert_text: format!(
                        "The endpoint seems to be misconfigured, and {} are possible on this endpoint",p
                    )
                },
                res.clone(),
            ));
            println!(
                "{}:{}",
                "Status".green().bold(),
                res.status.to_string().magenta()
            );
        } else {
            println!("REQUEST FAILED");
        }
        ret_val
    }

    pub async fn check_method_encoding(&self, auth: &Authorization) -> CheckRetVal {
        //roblem with order ouput
        //TODO FIX BUG ABOUT OUTPUT
        if let Some(compo) = &self.oas.components().unwrap().parameters {
            println!("pooooo");

            println!("{:?}", compo);

            for (i, y) in compo {
                println!(
                    "parameter i:{:?} ,y{:?}",
                    i,
                    y.inner(&self.oas_value).examples
                );
            }
        }

        let mut ret_val = CheckRetVal::default();
        let base_url = self.oas.servers().unwrap().get(0).unwrap().clone();

        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::POST {
                    if let Some(value_encod) = op.request_body.clone() {
                        let encoding = value_encod.inner(&self.oas_value).content;
                        // let encoding = op
                        //     .request_body
                        //     .clone()
                        //     .unwrap()
                        //     .inner(&self.oas_value)
                        //     .content;
                        /// THIS IS GUY - I USED THE * THINGY BECAUSE I needed an &str and it was only &&str because of the iter
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
                            println!("PAth: {} , encoding : {:?}", path, i);
                            let h = MHeader {
                                name: "Content-type".to_string(),
                                value: i.to_string(),
                            };
                            let req = AttackRequest::builder()
                                .uri(&base_url.url, path)
                                .auth(auth.clone())
                                .headers(vec![h])
                                .build();
                            print!("this is the req{:?}", req.headers);
                            if let Ok(res) = req.send_request(true).await {
                                println!("{:?}", res.status);
                                //logging request/response/description
                                ret_val
                                    .1
                                    .push(&req, &res, "Testing uncrypted traffic".to_string());
                                ret_val.0.push((
                                    ResponseData {
                                        location: path.clone(),
                                        alert_text: format!(
                                            "The endpoint: {} is not correctly configured for {} ",
                                            path, i
                                        ),
                                    },
                                    res.clone(),
                                ));
                            } else {
                                println!("REQUEST FAILED");
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
        let base_url = self.oas.servers().unwrap().get(0).unwrap().clone();

        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                /*
                 for  operations in  op.params()
                .iter_mut()
                .inner(&Value::Null)
                .filter_map(|s| {
                    if LIST_PARAM.contains(&s) { //contains from the list
                        Some(*s)
                    } else {
                        None
                    }
                })
                .param_in
                .filter_map(|e |
                {
                    if e == "query" ||
                })
                .collect::<Vec<Method>>();*/
                if m == Method::GET {
                    let mut param_is_good_to_send = false;

                    for (provider_item, value_to_send) in &provider_hash {
                        let mut params_vec = vec![];
                        let payload_get_param = create_payload_for_get(
                            &self.oas_value,
                            op,
                            Some(value_to_send.to_string()),
                        );
                        for parameter_item in payload_get_param {
                            if parameter_item.dm == QuePay::Query {
                                if LIST_PARAM.contains(&parameter_item.name.as_str()) {
                                    params_vec.push(parameter_item);
                                    param_is_good_to_send = true;
                                }
                            } else {
                                params_vec.push(parameter_item);
                            }
                        }

                        if param_is_good_to_send {
                            provider_vec.push(provider_item.to_string());
                            println!("SSRF GET: ----");
                            let req = AttackRequest::builder()
                                .uri(&base_url.url, path)
                                .parameters(params_vec.clone())
                                .auth(auth.clone())
                                .method(m)
                                .headers(vec![])
                                .auth(auth.clone())
                                .build();

                            if let Ok(res) = req.send_request(true).await {
                                //logging
                                //logging request/response/description
                                ret_val
                                    .1
                                    .push(&req, &res, "Testing ssrf for get ".to_string());
                                ret_val.0.push((
                                    ResponseData{
                                        location: path.clone(),
                                        alert_text: format!("The parameter {:?} seems to be vulerable to open-redirect on the {} endpoint",&params_vec.last().unwrap(),path)//TODO Chekc if is it the correct parameter
                                    },
                                res.clone(),
                                ));
                            } else {
                                println!("REQUEST FAILED");
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
            for (json_path) in oas_map.payload.map.keys() {
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
                            let base_url =
                                self.oas.servers().unwrap().iter().next().unwrap().clone();
                            provider_vec.push(provider_item.to_string());
                            let req = AttackRequest::builder()
                                .uri(&base_url.url, &oas_map.path.path)
                                .method(*m)
                                .headers(vec![])
                                .parameters(vec![])
                                .auth(auth.clone())
                                .payload(
                                    &change_payload(
                                        &oas_map.payload.payload,
                                        &json_path,
                                        json!(provider_value),
                                    )
                                    .to_string(),
                                )
                                .build();

                            print!("POST SSRF : ");

                            if let Ok(res) = req.send_request(true).await {
                                //logging request/response/description
                                ret_val
                                    .1
                                    .push(&req, &res, "Testing SSRF VALUES".to_string());
                                ret_val.0.push((
                                    ResponseData {
                                        location: oas_map.path.path.clone(),
                                        alert_text: format!(
                                            "This {} parameter on the {} endpoint seems to be vulerable to ssrf.", json_path[json_path.len() - 1],&param_to_test// json_path[json_path.len() - 1]
                                        ),
                                    },
                                    res.clone(),
                                ));
                                println!(
                                    "{}:{}",
                                    "Status".green().bold(),
                                    res.status.to_string().magenta()
                                );
                            } else {
                                println!("REQUEST FAILED");
                            }
                        }
                    }
                }
            }
        }
        (ret_val, provider_vec)
    }
}
