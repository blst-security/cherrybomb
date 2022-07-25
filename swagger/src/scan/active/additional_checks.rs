use super::*;
use serde_json::json;
// use mapper::digest::Method::POST;
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

    pub async fn check_min_max(&self, auth: &Authorization ) ->CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        for oas_map in self.payloads.iter() {
            for (json_path,schema) in &oas_map.payload.map {
                let test_vals = Vec::from([
                    schema.minimum.map(|min| ("minimum",min-1)),
                    schema.maximum.map(|max| ("maximum",max+1)),
                ]);
                for val in test_vals
                    .into_iter()
                    .flatten(){
                        for (m,_) in oas_map.
                        path.
                        path_item.
                        get_ops().
                        iter().
                        filter(|(m,_)|m == &Method::POST){
                            let url;
                            if let Some(servers) = &self.oas.servers(){
                                if let Some(s) = servers.first(){
                                    url = s.url.clone(); 
                                } else {continue};
                            } else {continue};
                            let req = AttackRequest::builder()
                                .uri(&url, &oas_map.path.path)
                                .method(*m)
                                .headers(vec![])
                                .parameters(vec![])
                                .auth(auth.clone())
                                .payload( &change_payload(&oas_map.payload.payload,json_path,json!(val.1)).to_string())
                                .build();
                            if let Ok(res) = req.send_request(true).await {
                                //logging request/response/description
                                ret_val.1.push(&req,&res,"Testing min/max values".to_string());
                                ret_val.0.push((
                                    ResponseData{
                                        location: oas_map.path.path.clone(),
                                        alert_text: format!("The {} for {} is not enforced by the server", val.0, json_path[json_path.len() - 1])
                                    },
                                    res.clone(),
                                ));
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
