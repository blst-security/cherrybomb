use super::utils::create_payload_for_get;
use super::*;
use colored::*;
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
    pub async fn check_access_control(&self, auth: &Authorization) -> CheckRetVal {
        let ret_val = CheckRetVal::default();
        println!("Security testing");
        if let Some(value) = self.oas.security(){
            println!("security: {:?}", value);
        }
        ret_val
    }
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param: Vec<RequestParameter> = Vec::new();
        let server = &self.oas.servers();
       // let mut param_object;
       let mut flag = false;
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                for i in op.params() {
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == "path".to_string()|| i.inner(&self.oas_value).param_in.to_string().to_lowercase() == "query"{
                            flag = true;
                            
                        }
                   
                   // if i.inner(&self.oas_value).name.to_lowercase().contains(&"id".to_string())
                    let mut param_obj ;
                    if flag{
                     //   param_object = i.inner(&self.oas_value).name;
                     let resp =  op.responses();
                     let data_resp = resp.get(&"200".to_string());
                     if let Some(value)= data_resp {
                        param_obj = value.inner(&self.oas_value).content.unwrap().into_values();
                        for i in param_obj {
                           println!("SHEMMMMMMAAAAA {:?}", i.schema.unwrap().inner(&self.oas_value).required);
                        }
                       // println!("PARAMMMM. {:?}", &param_obj);clear


                     }
                        if let Some(types) = i
                            .inner(&self.oas_value)
                            .schema()
                            .inner(&self.oas_value)
                            .schema_type
                        {
                            let mut value_to_send="2".to_string();
                            let mut var_int:i32= 2;
                            if types == "integer".to_string() {
                                if let Some(val) = i
                                    .inner(&self.oas_value)
                                    .examples
                                {
                                    if let Some((_ex, val)) = val.into_iter().next() {
                                        value_to_send = val.value.to_string();
                                        var_int = value_to_send.parse::<i32>().unwrap();
                                            
                                    }
                                    for n in var_int-1..var_int+1 {
                                    let param_to_send: RequestParameter = RequestParameter {
                                        name: i.inner(&self.oas_value).name.to_string(),
                                        value: n.to_string(),
                                        dm: QuePay::Query,
                                    };
                                    vec_param.push(param_to_send);
                                    let req = AttackRequest::builder()
                                        .uri(server,path)
                                        .method(*m)
                                        .auth(auth.clone())
                                        .build();
                                    if let Ok(res) = req.send_request(self.verbosity > 0).await {
                                        //logging request/response/description
                                        ret_val.1.push(
                                            &req,
                                            &res,
                                            "Testing for BOLA".to_string(),
                                        );
                                        ret_val.0.push((
                                            ResponseData {
                                                location: path.clone(),
                                                alert_text: format!(
                                    "The server: {} is not secure against https downgrade",
                                    &path
                                ),
                                                serverity: Level::Medium,
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
            }
        }
        ret_val
    }
}

