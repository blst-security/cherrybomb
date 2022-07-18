use super::{utils::create_string, *};
use futures::stream::Collect;
use serde_json::json;
// &use mapper::digest::Method::POST;
use colored::*;
const LIST_METHOD: [Method; 3] = [Method::GET, Method::POST, Method::PUT];
const LIST_CONTENT_TYPE: [&str; 2] = ["application/xml", "application/xml"];
const LIST_PARAM: [&str; 84] = [
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
                    // let test_vals = Vec::from([
                    //     schema.max_length.map(|int_max: String| ("maximum length",create_string(int_max))),
                    // ]);
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
        //proble with parameter in path to create query
        let mut ret_val = CheckRetVal::default();
        let server = self.oas.servers();
        let base_url = server
            .unwrap_or_default()
            .iter()
            .next()
            .unwrap()
            .url
            .clone();
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::GET {
                    for i in op.params().iter() {
                        let parameter = i.inner(&Value::Null).name.to_string();
                        if LIST_PARAM.contains(&parameter.as_str()) {
                            let req = AttackRequest::builder()
                                .uri(&base_url, path)
                                .parameters(vec![RequestParameter {
                                    name: parameter.to_string(),
                                    value: "https://blst.security.com".to_string(),
                                    dm: QuePay::Query,
                                }])
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
                                        alert_text: format!("The parameter {} seems to be vulerable to open-redirect on the {} endpoint",parameter,path)
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

    pub async fn check_parameter_pollution(
        &self,
        auth: &Authorization,
    ) -> (CheckRetVal, Vec<String>) {
        let mut ret_val = CheckRetVal::default();
        let server = self.oas.servers();
        //    let mut new_url:(String , String);
        let vec_polluted = vec!["blstparamtopollute".to_string()];
        let base_url = server.unwrap().iter().next().unwrap().clone();
        //let base_url = server.unwrap().get(0);
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                let _text = path.to_string();
                //   println!("{:?}", text);
                if m == Method::GET {
                    for i in op.params().iter_mut() {
                        let parameter = i.inner(&Value::Null);
                        //   let example = Some(parameter.examples.unwrap_or_default().get_key_value("d")));
                        let in_var = parameter.param_in.to_string();
                        let param_name = i.inner(&Value::Null).name.to_string();
                        let new_param = param_name.clone();
                        let _param_example = match in_var.as_str() {
                            "query" => {
                                let req = AttackRequest::builder()
                                    .uri(&base_url.url, path)
                                    .auth(auth.clone())
                                    .parameters(vec![
                                        RequestParameter {
                                            name: param_name.clone(),
                                            value: "blstparamtopollute".to_string(), // need to unwrap or defaultexample
                                            //  value: example.unwrap_or(serde_json::Value::String("blstparamtopollute".to_string())).to_string(),
                                            //      value: example.unwrap_or("blstparam".to_string()),
                                            dm: QuePay::Query,
                                        },
                                        RequestParameter {
                                            name: new_param,
                                            value: "blstparamtopollute".to_string(),
                                            dm: QuePay::Query,
                                        },
                                    ])
                                    .method(m)
                                    .headers(vec![])
                                    .auth(auth.clone())
                                    .build();
                                println!("Pollution");
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
                                            alert_text: format!("The endpoint {} seems to be vulerable to parameter pollution on the {} parameter",path,&param_name)
                                        },
                                        res.clone(),
                                    ));
                                } else {
                                    println!("REQUEST FAILED");
                                }
                            }
                            "path" => {}
                            _ => (),
                            //    if m == Method::POST {
                            // for i in op.params().iter_mut() {
                            //     println!("This is a post request");
                            //     let parameter = i.inner(&Value::Null);
                            //     let in_var = parameter.param_in.to_string();
                            //     let param_name = i.inner(&Value::Null).name.to_string();
                            //     let new_param = param_name.clone();

                            // }
                        };
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
        let mut ret_val = CheckRetVal::default();
        let mut vec_method: Vec<Method> = Vec::new();
        for (path, item) in &self.oas.get_paths() {
            for (m, _op) in item.get_ops() {
                vec_method.push(m);
            }

            // let mut requesst_map = HashMap::new();
            // request_map.insert(Method::GET, false);
            // request_map.insert(Method::POST, false);
            // //   request_map.insert(Method::DELETE, false);
            // request_map.insert(Method::PUT, false);
            // match m {
            //     Method::GET => {
            //         let mut a = request_map.get_mut(&Method::GET).unwrap_or(&mut true);
            //         a = &mut true;
            //     }
            //     Method::PUT => {
            //         let mut a = request_map.get_mut(&Method::PUT).unwrap_or(&mut true);
            //         a = &mut true;
            //     }
            //     Method::POST => {
            //         let mut a = request_map.get_mut(&Method::POST).unwrap_or(&mut true);
            //         a = &mut true
            //     }
            //     _ => (),
            // };

            // let iter = request_map.iter().filter(|&(_, v)| v != &true);
            let methodes = LIST_METHOD
                .iter()
                .filter_map(|s| {
                    if !vec_method.contains(&s) {
                        Some(*s)
                    } else {
                        None
                    }
                })
                .collect::<Vec<Method>>();
            for i in methodes {
                println!("Method permissions:{:?}", i);
                let value_to_add =
                    Self::send_request_to_test(&self, i, (&path).to_string(), &auth).await;

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
        let base_url = swagger
            .oas
            .servers()
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .clone();

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
        let mut ret_val = CheckRetVal::default();
        let base_url = self
            .oas
            .servers()
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .url
            .clone();

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
                                .uri(&base_url, &path)
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
                                            &path, i
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
        return ret_val;
    }
}
