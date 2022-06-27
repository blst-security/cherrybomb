use super::*;
use serde_json::json;
use mapper::digest::Method::POST;
use colored::*;


pub fn change_payload(orig:& Value,path:&[String],new_val:Value)->Value{
    let mut change=&mut json!(null);
    let mut ret = orig.clone();
    for path_part in path.iter() {
        change = &mut ret[path_part];
    }
    *change = new_val;
    ret.clone()
}
impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_min_max(&self, auth: &Authorization) -> CheckRet {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        for (path, (payload, map)) in &self.static_props {
            for (json_path, schema) in map {
                let mut test_vals: Vec<_> = vec![];
                if let Some(min) = schema.minimum {
                    test_vals.push(("minimum", min - 1));
                }
                if let Some(max) = schema.maximum {
                    test_vals.push(("maximum", max + 1));
                }
                for val in test_vals.iter() {
                    if let Some(url) = get_path_urls(self.oas.get_paths().get(path).unwrap(),
                                                     self.oas.servers()).iter().find(|&&(method, _)| method == POST) {
                        let req = AttackRequest::builder()
                            .uri(&url.1, path)
                            .method(url.0)
                            .headers(vec![])
                            .parameters(vec![])
                            .auth(auth.clone())
                            .payload( &change_payload(payload,json_path,json!(val.1)).to_string())
                            .build();
                        if let Ok(res) = req.send_request(true).await {
                            //logging request/response/description
                            attack_log.push(&req,&res,"Testing min/max values".to_string());
                            let res_data = ResponseData {
                                location: path.clone(),
                                alert_text: format!("The {} for {} is not enforced by the server", val.0, json_path[json_path.len() - 1]),
                            };
                            ret_val.push((
                                res_data,
                                res.clone()
                            ));
                            println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                        } else {
                            println!("REQUEST FAILED");
                        }
                    }
                }
            }
        }
        (ret_val,attack_log)
    }
}
