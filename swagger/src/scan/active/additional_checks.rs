use serde_json::json;
use colored::*;
// use std::time::{Duration, Instant, SystemTime};
use super::{utils::create_payload_for_get, *};

const LIST_METHOD: [Method; 3] = [Method::GET, Method::POST, Method::PUT];
// const LIST_CONTENT_TYPE: [&str; 2] = ["application/xml", "application/xml"];
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
                if let Some(max_len) = schema.max_length {
                    let new_string = iter::repeat(['B','L','S','T']).
                    flatten().
                    take(max_len.try_into().unwrap()).
                    collect::<String>();
                    for (m, _) in oas_map
                            .path
                            .path_item
                            .get_ops()
                            .iter()
                            .filter(|(m, _)| m == &Method::POST)
                        {
                            let url= &self.oas
                                .servers()
                                .and_then(|servers| servers.first().cloned());
                            if let Some(url) = url {
                                let req = AttackRequest::builder()
                                    .uri(&url.url, &oas_map.path.path)
                                    .method(*m)
                                    .headers(vec![])
                                .parameters(vec![])
                                .auth(auth.clone())
                                .payload(
                                    &change_payload(
                                        &oas_map.payload.payload,
                                        json_path,
                                        json!(&new_string),
                                    )
                                    .to_string(),
                                )
                                .build();
                                dbg!(&req);
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
                                                schema.max_length,
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
            for (m, op) in item.get_ops()
                .into_iter()
                .filter(|(m, _)| m == &Method::GET) {
                let vec_param = create_payload_for_get(
                    &self.oas_value,
                    op,
                    Some("https://blst.security.com".to_string()),
                );
                for param_item in &vec_param {
                    if param_item.dm == QuePay::Query && LIST_PARAM.contains(&param_item.name.as_str()){
                        let param_to_redirect = param_item.name.clone();
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
        ret_val
    }

    pub async fn check_parameter_pollution(
        &self,
        auth: &Authorization,)
        -> (CheckRetVal, Vec<String>) {
        let mut ret_val = CheckRetVal::default();
        // let server = self.oas.servers();
        let vec_polluted = vec![String::from("blstparamtopollute")];
        let base_url = &self.oas.servers().and_then(|servers| servers.first().cloned());

        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops()
                .into_iter()
                .filter(|(m, _)| m == &Method::GET) {
                let vec_param = create_payload_for_get(&self.oas_value, op, None);

                if let Some(url) = base_url {
                    for param in vec_param.iter() {
                        let mut polluted_params = vec_param.clone();
                        polluted_params.push(param.clone());
                        let req = AttackRequest::builder()
                            .uri(url.url.as_str(),path)
                            .parameters(polluted_params)
                            .method(m)
                            .headers(vec![])
                            .auth(auth.clone())
                            .build();
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
                                    alert_text: format!("The endpoint {} seems to be vulnerable to parameter pollution on the {} parameter",path,vec_param.last().unwrap().name)
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
        (ret_val, vec_polluted)
    }

    pub async fn check_ssl(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        if let Some(server_list) = self.oas.servers() {
            for server in server_list.iter() {
                let mut new_url = server.url.clone();
                if &new_url[..5] == "https" { //todo maybe change this
                    new_url.replace_range(0..5, "http");
                    let req = AttackRequest::builder()
                        .uri(&new_url, "")
                        .auth(auth.clone())
                        .build();
                    println!("{}", req);
                    if let Ok(res) = req.send_request(true).await {
                        //logging request/response/description
                        ret_val
                            .1
                            .push(&req, &res, "Testing non SSL access traffic".to_string());
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
        }
        ret_val
    }

    pub async fn check_method_permissions(&self, auth: &Authorization) -> CheckRetVal {
        //// reformat get with path parameter
        let mut ret_val = CheckRetVal::default();
        let base_url = &self.oas.servers().and_then(|servers| servers.first().cloned());
        for (path, item) in &self.oas.get_paths() {
            let current_method_set = item.get_ops()
                .iter()
                .map(|(m,_)| m)
                .cloned()
                .collect::<HashSet<_>>();
            let all_method_set = HashSet::from(LIST_METHOD);
            for method in all_method_set.difference(&current_method_set) {
                if let Some(url) = base_url {
                    let req = AttackRequest::builder()
                        .uri(&url.url, path)
                        .auth(auth.clone())
                        .method(*method)
                        .headers(vec![])
                        .build();
                    if let Ok(res) = req.send_request(true).await {
                        //logging request/response/description
                        ret_val
                            .1
                            .push(&req, &res, "Test method permission".to_string());
                        ret_val.0.push((
                            ResponseData {
                                location: path.clone(),
                                alert_text: format!(
                                    "The {} endpoint accepts {:?} although its not documented to", path, method
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
                }
            }
        }
        ret_val
    }


    // pub async fn check_method_encoding(&self, auth: &Authorization) -> CheckRetVal {
    //     //roblem with order ouput
    //     //TODO FIX BUG ABOUT OUTPUT
    //     if let Some(compo) = &self.oas.components().unwrap().parameters {
    //         for (i, y) in compo {
    //             println!(
    //                 "parameter i:{:?} ,y{:?}",
    //                 i,
    //                 y.inner(&self.oas_value).examples
    //             );
    //         }
    //     }
    //     let mut ret_val = CheckRetVal::default();
    //     let base_url = self.oas.servers().unwrap().get(0).unwrap().clone(); //todo ouch
    //     for (path, item) in &self.oas.get_paths() {
    //         for (m, op) in item.get_ops() {
    //             if m == Method::POST {
    //                 if let Some(value_encod) = op.request_body.clone() {
    //                     let encoding = value_encod.inner(&self.oas_value).content;
    //                     // let encoding = op
    //                     //     .request_body
    //                     //     .clone()
    //                     //     .unwrap()
    //                     //     .inner(&self.oas_value)
    //                     //     .content;
    //                     // THIS IS GUY - I USED THE * THINGY BECAUSE I needed an &str and it was only &&str because of the iter
    //                     let encoding = LIST_CONTENT_TYPE
    //                         .iter()
    //                         .filter_map(|t| {
    //                             if !encoding.contains_key(*t) {
    //                                 Some(*t)
    //                             } else {
    //                                 None
    //                             }
    //                         })
    //                         .collect::<Vec<&str>>();
    //                         dbg!(&encoding);
    //                     for i in encoding {
    //                         println!("PAth: {} , encoding : {:?}", path, i);
    //                         let h = MHeader {
    //                             name: "Content-type".to_string(),
    //                             value: i.to_string(),
    //                         };
    //                         let req = AttackRequest::builder()
    //                             .uri(&base_url.url, path)
    //                             .auth(auth.clone())
    //                             .headers(vec![h])
    //                             .build();
    //                         print!("this is the req{:?}", req.headers);
    //                         if let Ok(res) = req.send_request(true).await {
    //                             println!("{:?}", res.status);
    //                             //logging request/response/description
    //                             ret_val
    //                                 .1
    //                                 .push(&req, &res, "Testing uncrypted traffic".to_string());
    //                             ret_val.0.push((
    //                                 ResponseData {
    //                                     location: path.clone(),
    //                                     alert_text: format!(
    //                                         "The endpoint: {} is not correctly configured for {} ",
    //                                         path, i
    //                                     ),
    //                                 },
    //                                 res.clone(),
    //                             ));
    //                         } else {
    //                             println!("REQUEST FAILED");
    //                         }
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     ret_val
    // }
    

    pub async fn check_for_ssrf(&self, auth: &Authorization) -> (CheckRetVal, Vec<String>) {
        let mut ret_val = CheckRetVal::default();
        let mut provider_vec = vec![];
        let provider_hash = HashMap::from([
            ("Amazon", "http://169.254.169.254/"),
            ("Google", "http://169.254.169.254/computeMetadata/v1/"),
            ("Digital", "http://169.254.169.254/metadata/v1.json"),
            ("Azure", "http://169.254.169.254/metadata/v1/maintenance"),
        ]);
        let base_url = self.oas.servers().unwrap().get(0).unwrap().clone(); //todo ouch
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                
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
                            .method(m.to_owned())
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
                            if let Some(server) = self.oas.servers().and_then(|servers| servers.first().cloned()){
                                
                                provider_vec.push(provider_item.to_string());
                                let req = AttackRequest::builder()
                                    .uri(&server.url, &oas_map.path.path)
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
        }
        (ret_val, provider_vec)
    }

//     pub async fn check_xml_bomb(&self, auth: &Authorization) -> (CheckRetVal, Vec<Duration>) {
//         let body = format!(
//             r#"
//         <?xml version="1.0" encoding="utf-8"?>
// <!DOCTYPE lolz [
// <!ENTITY lol "lol">
// <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
// <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
// <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
// <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
// <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
// <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
// <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
// <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
// <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
// ]>
// <lolz>&lol9;</lolz
//         "#
//         );
//         let mut ret_val = CheckRetVal::default();
//         let mut vec_time = vec![];
//         //     if let Some(content) =  &op.request_body{
//         for oas_map in self.payloads.iter() {
//             for (json_path, schema) in &oas_map.payload.map {
//                 // .filter_map(|x| x){
//                 for (m, _operation) in oas_map
//                     .path
//                     .path_item
//                     .get_ops()
//                     .iter()
//                     .filter(|(m, _)| m == &Method::POST)
//                     .filter(|(_method, operation)| {
//                         operation
//                             .request_body
//                             .clone()
//                             .unwrap_or_default()
//                             .inner(&self.oas_value)
//                             .content
//                             .into_keys()
//                             .collect::<Vec<String>>()
//                             .contains(&"application/xml".to_string())

//                         // if let Some(value) =   &operation.request_body{
//                         //      for ( string_item, Mediatype_item) in  &value.inner(&self.oas_value).content  {
//                         //         println!("{:?}", string_item);
//                         //         if string_item == "application/xml"{
//                         //             println!("THere is one least");
//                         //         }
//                         //     ;
//                         // }
//                     })
//                     .next()
//                 //       .filter(|(operation)|   operation.1.request_body.unwrap().clone().inner(&self.oas_value).content.keys())
//                 {
//                     //  println!("{:?}", operation);
//                     println!("ENCONDING {:?}", &oas_map.path.path);
//                     let h = MHeader {
//                         name: "Content-type".to_string(),
//                         value: "application/xml".to_string(),
//                     };
//                     let base_url = self.oas.servers().unwrap().iter().next().unwrap().clone();
//                     let req = AttackRequest::builder()
//                         .uri(&base_url.url, &oas_map.path.path)
//                         .method(*m)
//                         .headers(vec![h])
//                         .payload(&body)
//                         .parameters(vec![])
//                         .auth(auth.clone())
//                         .build();

//                     print!("XML BOMB : ");

//                     /* let start = Instant::now();
//                     expensive_function();
//                     let duration = start.elapsed(); */
//                     let start = Instant::now();
//                     if let Ok(res) = req.send_request(true).await {
//                         //logging request/response/description
//                         ret_val.1.push(&req, &res, "Test for XML BOMB".to_string());
//                         ret_val.0.push((
//                             ResponseData {
//                                 location: oas_map.path.path.clone(),
//                                 alert_text: format!(
//                                         "This  parameter on the endpoint seems to be vulerable to ssrf.", // json_path[json_path.len() - 1]
//                                     ),
//                             },
//                             res.clone(),
//                         ));
//                         println!(
//                             "{}:{}",
//                             "Status".green().bold(),
//                             res.status.to_string().magenta()
//                         );
//                     } else {
//                         println!("REQUEST FAILED");
//                     }
//                     vec_time.push(start.elapsed());
//                 }
//             }
//         }
//         (ret_val, vec_time)
//     }
}
