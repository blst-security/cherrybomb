use super::utils::create_payload_for_get;
use super::*;
// use colored::*;
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
                        let payload_get_param = create_payload_for_get(
                            &self.oas_value,
                            op,
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
                                    ret_val.1.push(&req, &response, "Testing  /max values".to_string());
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
                                ret_val.1.push(&req, &response, "Testing  /max values".to_string());
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
