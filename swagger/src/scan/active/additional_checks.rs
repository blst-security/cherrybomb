use std::iter;
use super::*;
use serde_json::json;
use mapper::digest::Method::POST;
// use std::collections::HashMap;
/*#[macro_export]
macro_rules! drop_in_json {
    ( $json:ident,$new_val:ident, $( ($path:ident),* ) => {
        $json([$path])* = $new_val;
    }
}*/

pub fn change_payload(orig:& Value,path:&Vec<String>,new_val:Value)->Value{
    let mut change=&mut json!(null);
    let mut ret = orig.clone();
    for path_part in path.iter() {
        change = &mut ret[path_part];
    }
    *change = new_val;
    ret.clone()
}
impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_min_max(&self, auth: &Authorization) -> Vec<(String, AttackResponse)> {
        let mut ret_val: Vec<(String, AttackResponse)> = vec![];
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
                    //*change = json!(val.1);
                    if let Some(url) = get_path_urls(self.oas.get_paths().get(path).unwrap(),
                                                     self.oas.servers()).iter().find(|&&(method, _)| method == POST) {
                        let req = AttackRequest::builder()
                            .uri(&url.1, &path)
                            .method(url.0)
                            .headers(vec![])
                            .parameters(vec![])
                            .auth(auth.clone())
                            .payload( &change_payload(payload,json_path,json!(val.1)).to_string())
                            .build();
                        if let Ok(res) = req.send_request(true).await {
                            ret_val.push((String::from(format!("The {} defined on {} for {} is not \
                            enforced by the server", val.0, path, json_path[json_path.len() - 1])), res.clone()));
                            use colored::*;
                            println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                        } else {
                            println!("REQUEST FAILED");
                        }
                    }
                }
            }
        }
        ret_val
    }
}
