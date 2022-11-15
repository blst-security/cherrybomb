use super::utils::create_payload_for_get;
use super::*;
// use colored::*;
use serde_json::json;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_authentication_for_post(&self, _auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        for oas_map in self.payloads.iter() {
            for _schema in oas_map.payload.map.values() {
                for (m, op) in oas_map.path.path_item.get_ops().iter() {
                    let vec_param =
                        create_payload_for_get(&self.oas_value, op, Some("".to_string()));
                    if let Some(_value) = &op.security {
                        let req = AttackRequest::builder()
                            .servers(self.oas.servers(), true)
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
                                    alert_text: format!("The endpoint seems to be not secure {:?}, with the method : {} ", &oas_map.path.path, m ),
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
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::GET {
                    let vec_param =
                        create_payload_for_get(&self.oas_value, op, Some("".to_string()));
                    let req = AttackRequest::builder()
                        .servers(self.oas.servers(), true)
                        .path(&path.clone())
                        .method(m)
                        .headers(vec![])
                        .parameters(vec_param.clone())
                        .build();
                    let response_vector = req.send_request_all_servers(self.verbosity > 0).await;
                    for response in response_vector {
                        ret_val
                            .1
                            .push(&req, &response, "Testing without auth".to_string());
                        ret_val.0.push((
                                        ResponseData {
                                            location: path.to_string(),
                                            alert_text: format!("The endpoint seems to be not secure {:?}, with the method : {} ", &path, m ),
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
