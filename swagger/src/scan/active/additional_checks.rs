use super::utils::create_payload_for_get;
use super::*;
// use colored::*;
use serde_json::json;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_method_permissions(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
         for (path, item) in &self.oas.get_paths() {
            let current_method_set = item
                .get_ops()
                .iter()
                .map(|(m, _)| m)
                .cloned()
                .collect::<HashSet<_>>();

            let vec_param =
                create_payload_for_get(&self.oas_value, item.get_ops()[0].1, Some("".to_string()));

            let all_method_set = HashSet::from(LIST_METHOD);
            for method in all_method_set.difference(&current_method_set).cloned() {
                    let req = AttackRequest::builder()
                        .servers( self.oas.servers(), true)
                        .path(path)
                        .parameters(vec_param.clone())
                        .auth(auth.clone())
                        .method(method)
                        .headers(vec![])
                        .build();
                    if let Ok(res) = req.send_request(self.verbosity > 0).await {
                        //logging request/response/description
                        ret_val
                            .1
                            .push(&req, &res, "Test method permission".to_string());
                        ret_val.0.push((
                            ResponseData {
                                location: path.clone(),
                                alert_text: format!(
                                    "The {} endpoint accepts {:?} although its not documented to",
                                    path, method
                                ),
                                serverity: Level::High,
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
