use crate::active::utils::send_req;

///use super::utils::create_payload_for_get;
use super::*;
use colored::*;
use futures::TryFutureExt;
use reqwest::Client;
use reqwest::{self, Url};
use serde::ser::Error;
use serde_json::json;
use utils;
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
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param_values: Vec<RequestParameter> = Vec::new();

        let server = &self.oas.servers();
        let mut UUID_HASH: HashMap<String, Vec<String>> = HashMap::new();
        for (path, item) in &self.oas.get_paths() {
            let mut flag = false;
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                for i in op.params() {
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == "path".to_string()
                    {
                        //|| i.inner(&self.oas_value).param_in.to_string().to_lowercase() == "query"
                        flag = true;
                        break;
                    }
                }
                if !flag {
                    // if no path param
                    let responses = op.responses();
                    //  dbg!("responses {:?}", &responses);
                    let data_resp = responses.get(&"200".to_string());
                    //println!("dataaaa {:?}", data_resp);
                    if let Some(v) = data_resp {
                        // let values = v.inner(&self.oas_value).content;
                        let values = v
                            .inner(&self.oas_value)
                            .content
                            .unwrap_or_default()
                            .into_values();
                        for i in values {
                            //  println!("HHHHH {:?}", i.schema);
                            if i.schema
                                .as_ref()
                                .unwrap()
                                .inner(&self.oas_value)
                                .schema_type
                                .unwrap_or_default()
                                .to_string()
                                == "array".to_string()
                            {
                                //if array in response
                                let val = i
                                    .schema
                                    .unwrap()
                                    .inner(&self.oas_value)
                                    .items
                                    .unwrap_or_default(); //
                                                          //println!("items, {:?}", val);
                                                          // println!("compo {:?}", val.inner(&self.oas_value).properties);
                                                          //let compo = val.inner(&self.oas_value).items.unwrap_or_default().inner(&self.oas_value);
                                                          //println!("COMPO {:?}", compo);
                                let var_name: Vec<String> = val
                                    .inner(&self.oas_value)
                                    .properties
                                    .unwrap()
                                    .keys()
                                    .cloned()
                                    .collect();
                                let mut liste_of_values: Vec<String> = Vec::new();
                                for value in var_name {
                                    println!("values: {:?}", value); //
                                    if value.contains(&"id".to_string()) {
                                        //check if val contains ID in the response
                                        let mut base = "".to_string();
                                        //   if let Some(value)= &self.oas.servers() {
                                        //     base = value.get(0).unwrap().url.to_string();
                                        //   }
                                        println!("PATH {:?}", path);
                                        println!("this is the hash {:?}", UUID_HASH);
                                        let vec_of_values =send_req(
                                          path.to_string(),
                                          &"http://localhost:8888/".to_string(),&value
                                      )
                                      .await;
                            
                                        UUID_HASH.insert(value.clone(), vec_of_values);

                                       
                                    }
                                }
                               

                                    /*

                                        //sending the request
                                        println!("PATH TO SEND :   {:?} ", path  );
                                        let req = AttackRequest::builder()
                                        .uri(&server, path)
                                        .method(Method::GET)
                                        .headers(vec![])
                                        .auth(auth.clone())
                                        .build();

                                    if let Ok(response) = req.send_request(self.verbosity > 0).await {
                                        //logging request/response/description
                                    //   println!("response {:?} ",response);
                                       println!("response payload : {:?}", response);

                                     } else {
                                        println!("REQUEST FAILED");
                                    }
                                    */
                                
                            }
                        }
                    }
                }
            }
        }
        UUID_HASH.retain(|_, v| v.len()>=1); // remove all pair with 0 length
        let mut vec_of_keys = Vec::new();// get all the key in a vec
        for key in UUID_HASH.keys(){
            vec_of_keys.push(key.clone());
        }
        println!("THIS IS THE FINAL HASHMAP : {:?}", UUID_HASH);

        for (path, item) in &self.oas.get_paths() {

        for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
            let mut vec_param:Vec<RequestParameter> = Vec::new(); 
            for i in op.params() {
                     //TODO Check if there is only one param
                        let mut type_param;
                        match &i.inner(&self.oas_value).param_in.to_lowercase(){
                            path=>{type_param = QuePay::Path},
                            query => {type_param = QuePay::Query},
                        }
                        let param_name = &i.inner(&self.oas_value).name;
                         if vec_of_keys.contains(&param_name) {
                            let value_to_send 
                            = &UUID_HASH.get(param_name).unwrap()[0];
                            vec_param.push(RequestParameter {// TODO check if others values are ok
                                name: param_name.to_string(),
                                value: value_to_send.to_string(),
                                dm: type_param,
                            });


                         }
                       
                            

                    

            }

            }
        }
        return ret_val;
    }
}
