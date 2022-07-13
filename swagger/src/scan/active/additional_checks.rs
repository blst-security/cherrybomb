use super::{*, utils::create_string};
use serde_json::json;
// &use mapper::digest::Method::POST;
use colored::*;
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
                       //
                        //println!("popopopopopopo");

                    // .filter_map(|x| x){
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
                        //    dbg!(&req);
                        print!(" Min mAx : ");

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
    
    pub async fn check_string_length_max(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        
        for oas_map in self.payloads.iter() {
            for (json_path,schema) in &oas_map.payload.map {
                if let Some(int_max) = schema.max_length{
                    let  new_string = create_string(int_max).clone();
                    


                
                let test_vals = Vec::from([(schema.max_length ,&new_string)]);
                // let test_vals = Vec::from([
                //     schema.max_length.map(|int_max: String| ("maximum length",create_string(int_max))),
                // ]);
                for val in test_vals{
                    // .into_iter()
                    // .flatten(){
                        for (m,_) in oas_map
                        .path
                        .path_item
                        .get_ops()
                        .iter()
                        .filter(|(m,_)|m == &Method::POST){
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
                                ret_val.1.push(&req,&res,"Testing min/max length".to_string());
                                ret_val.0.push((
                                    ResponseData{
                                        location: oas_map.path.path.clone(),
                                        alert_text: format!("The {:?} for {} is not enforced by the server",val.0,json_path[json_path.len() - 1])
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

    }
    ret_val
}
pub async fn check_open_redirect(&self, auth: &Authorization) -> CheckRetVal { //proble with parameter in path to create query
    let mut ret_val = CheckRetVal::default();
    for base_url in self.oas.servers().unwrap_or_default() {
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops() {
                if m == Method::GET {
                    for i in op.params().iter() {
                        let parameter = i.inner(&Value::Null).name.to_string();
                        if LIST_PARAM.contains(&parameter.as_str()) {
                            let req = AttackRequest::builder()
                                .uri(&base_url.url, path)
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
                                ret_val.1.push(&req,&res,"Testing open-redirect".to_string());
                                ret_val.0.push((
                                    ResponseData{
                                        location: path.clone(),
                                        alert_text: format!("The parameter {} seems to be vulerable to open-redirect on the {} endpoint",parameter.to_string(),path)
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
    }
    ret_val

}
pub async fn check_parameter_pollution(&self, auth: &Authorization) -> (CheckRetVal, Vec<String>) {
    let mut ret_val = CheckRetVal::default();
    let server = self.oas.servers();
    //    let mut new_url:(String , String);
    let mut vec_polluted = vec!["blstparamtopollute".to_string()];
    let base_url = server.unwrap().iter().next().unwrap().clone();
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
                        let param_example = match in_var.as_str() {
                            "query" => {
                                let req = AttackRequest::builder()
                                    .uri(&base_url.url, &path)
                                    .auth(auth.clone())
                                    .parameters(vec![
                                        RequestParameter {
                                            name: param_name.clone(),
                                           value: "blstparamtopollute".to_string(),// need to unwrap or defaultexample
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
                                    ret_val.1.push(&req,&res," Testing get parameter pollution ".to_string());
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
    let mut ret_val = CheckRetVal::default();
    if let Some(server_url) = self.oas.servers() {
        for i in server_url {
            // let format_url = create_http_url(i.url);
            let mut new_url = i.url;
           // let format_u  = &new_url[..5];
          //  &new_url[..5]="http";
          if new_url.contains("https"){
            &new_url.replace_range(0..5, "http");
          }
          
            let req = AttackRequest::builder()
                .uri(&new_url, "")
                .auth(auth.clone())
                .build();
            if let Ok(res) = req.send_request(true).await {
                //logging request/response/description
                ret_val.1.push(&req,&res,"Testing uncrypted traffic".to_string());
                                ret_val.0.push((
                                    ResponseData{
                                        location: new_url.clone(),
                                        alert_text: format!("The server: {} is not secure against https downgrade",&new_url)
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
