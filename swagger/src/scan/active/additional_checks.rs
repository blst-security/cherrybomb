use super::utils::create_payload_for_get;
use super::*;
// use colored::*;
use serde_json::json;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_method_encoding(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();

        for oas_map in self.payloads.iter() {
            for (_json_path, _schema) in &oas_map.payload.map {
                for (m, op) in oas_map
                    .path
                    .path_item
                    //.filter(|| path_item==p)
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
                            println!("PAth: {} , encoding : {:?}", oas_map.path.path, i);
                            let h = MHeader {
                                name: "Content-type".to_string(),
                                value: i.to_string(),
                            };
                            let vec_param =
                                create_payload_for_get(&self.oas_value, op, Some("".to_string()));
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
    /*
    pub async fn check_method_encoding(&self, auth: &Authorization) -> CheckRetVal {
        //roblem with order ouput
        //TODO FIX BUG ABOUT OUTPUT
        // if let Some(compo) = &self.oas.components().unwrap().parameters {
        //     for (i, y) in compo {
        //         println!(
        //             "parameter i:{:?} ,y{:?}",
        //             i,
        //             y.inner(&self.oas_value).examples
        //         );
        //     }
        // }

        let mut ret_val = CheckRetVal::default();

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
                            let vec_param =
                            create_payload_for_get(&self.oas_value, op, Some("".to_string()));

                            let req = AttackRequest::builder()
                                .servers(self.oas.servers(), true)
                                .path(path)
                                .parameters(vec_param)
                                .auth(auth.clone())
                                .headers(vec![h])
                                .build();
                            let response_vector =
                                req.send_request_all_servers(self.verbosity > 0).await;
                            for response in response_vector {
                                ret_val
                                    .1
                                    .push(&req, &response, "Testing misconfiguration for encoding".to_string());
                                ret_val.0.push((
                                    ResponseData {
                                        location: path.clone(),
                                        alert_text: format!(
                                            "The endpoint: {} is not correctly configured for {} ",
                                            path, i
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
    */
}

const LIST_METHOD: [Method; 3] = [Method::GET, Method::POST, Method::PUT];
const LIST_CONTENT_TYPE: [&str; 2] = ["application/xml", "application/xml"];
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
