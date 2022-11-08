use crate::active::utils::{send_req, recursive_func_to_find};

///use super::utils::create_payload_for_get;
use super::*;
use super::utils::find_id_param;
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
    pub async fn check_of_param (&self, auth: &Authorization ) -> CheckRetVal {
        let mut vec_param : Vec<String> = Vec::new();
        let mut ret_val = CheckRetVal::default();
        let mut flag = false;
        for (path, item) in &self.oas.get_paths() {
            for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
                println!("THE PATH {}", path);

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
                        let values = v
                        .inner(&self.oas_value)
                        .content
                        .unwrap_or_default()
                        .into_values();
                    for i in values {
                         if i.schema
                            .as_ref()
                            .unwrap()
                            .inner(&self.oas_value)
                            .schema_type
                            .unwrap_or_default()    
                            .to_string()
                            == "array".to_string()

                        {
                            let val = i
                            .schema;
                        
                        if let Some(schema)= val{
                        println!("the result {:?}",recursive_func_to_find(&self.oas_value, schema, &mut vec_param));
                            
                        println!("###########");


                         println!(" ");
                        println!("###########");
                        }
                    }
                }
                    }
                }
            }
        }
        ret_val
    }



    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param_values: Vec<RequestParameter> = Vec::new();
        let mut vec_param : Vec<String> = Vec::new();

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
                    let data_resp = responses.get(&"200".to_string());
                    //println!("dataaaa {:?}", data_resp);
                    if let Some(v) = data_resp { 
                         let values = v
                            .inner(&self.oas_value)
                            .content
                            .unwrap_or_default()
                            .into_values();
                        for i in values {
                             if i.schema
                                .as_ref()
                                .unwrap()
                                .inner(&self.oas_value)
                                .schema_type
                                .unwrap_or_default()
                                .to_string()
                                == "array".to_string()

                            {
                                let schema = i.schema.unwrap();

                                //if array in response
                                let val = schema
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
                                recursive_func_to_find(&self.oas_value, schema, &mut vec_param);
                                let set: HashSet<_> = vec_param.drain(..).collect(); // dedup
                                println!("the result is {:?}", vec_param);
                                vec_param.extend(set.into_iter());
                                 for value in &vec_param {
                                        
                                        println!("PATH {:?},PARAMETER NAME IS : {}", path, value);
                                        let mut vec_of_values =send_req(
                                          path.to_string(),
                                          &"http://localhost:8888/".to_string(),&value
                                      )
                                      .await;
                                      println!("The key is {} and the vec of values is {:?} ", value , vec_of_values);
                                        if let Some(V) = UUID_HASH.get_mut(value) {
                                            V.append(&mut vec_of_values);
                                        }
                                        else {
                                            UUID_HASH.insert(value.clone(), vec_of_values.clone());
                                        }
                                       
                                    
                                }
                               
 
                
                                
                            }
                        }
                    }
                }
                //TODO! check simple response
                // if !flag {
                //     // if no path param
                //     let responses = op.responses();
                //     let data_resp = responses.get(&"200".to_string());
                //     //println!("dataaaa {:?}", data_resp);
                //     if let Some(v) = data_resp {
                //         let values = v
                //         .inner(&self.oas_value)
                //         .content
                //         .unwrap_or_default()
                //         .into_values();
                //         //
                        
                    

                //     }
                // }




            }
        }
       // println!(" real hash before retatin : {:?}", UUID_HASH);
     //   UUID_HASH.retain(|_, v| v.len()>=1); // remove all pair with 0 length
        let mut vec_of_keys = Vec::new();// get all the key in a vec
        for key in UUID_HASH.keys(){
         
            vec_of_keys.push(key.clone());
        }
        println!("THIS IS THE FINAL HASHMAP : {:?}", UUID_HASH);
        for (path, item) in &self.oas.get_paths() {
        for (m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) {
            let mut vec_params:Vec<RequestParameter> = Vec::new(); 
            println!("THE PATH2: {}", path);
            for i in op.params() {
                     //TODO Check if there is only one param
                        let mut type_param;
                        match &i.inner(&self.oas_value).param_in.to_lowercase(){
                            path=>{type_param = QuePay::Path},
                            query => {type_param = QuePay::Query},
                        }
                        let param_name = &i.inner(&self.oas_value).name;
                        println!("this is the param name {}", param_name);
                      //  println!("the vec_ param {:?} ", vec_param);
                        let mut flag  = false;
                        let mut elem_to_search="".to_string();
                        for i in &vec_param{
                            if param_name.to_lowercase() == i.to_lowercase(){
                                flag = true;
                                elem_to_search = i.to_string();
                            }
                        }
                            if flag{
                     //    if vec_param.contains(&param_name.to_lowercase()) { //check if param equal to the keys
                            println!("is equal {}", param_name.to_lowercase());
                            let value_to_send 
                            = &UUID_HASH.get(&elem_to_search).unwrap()[0];
                            vec_params.push(RequestParameter {// TODO check if others values are ok
                                name: param_name.to_string(),
                                value: value_to_send.to_string(),
                                dm: type_param,
                            });
                             
                                        //sending the request
                                      //  println!("PATH TO SEND :   {:?} ", path  );
                                      let req = AttackRequest::builder()
                                      .uri(&server, path)
                                      .parameters(vec_params.clone())
                                      .auth(auth.clone())
                                      .method(Method::GET)
                                      .headers(vec![])
                                      .auth(auth.clone())
                                      .build();
                                  if let Ok(res) = req.send_request(self.verbosity > 0).await {
                                      //logging
                                      //logging request/response/description
                                      ret_val
                                          .1
                                          .push(&req, &res, "Testing open-redirect".to_string());
                                      ret_val.0.push((
                                      ResponseData{
                                          location: path.clone(),
                                          alert_text: format!("The parameter {} seems to be vulnerable to open-redirect, location: {}  ",elem_to_search,path),
                                        serverity: Level::High,
                                      },
                                  res.clone(),
                                  ));
                                  } else {
                                      println!("{}", "REQUEST FAILED".red());
                                  }
                                    
                            

                         }
            }

            }
        }
        return ret_val;
    }
}
