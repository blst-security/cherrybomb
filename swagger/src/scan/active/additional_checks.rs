use std::collections::hash_set;

 
///use super::utils::create_payload_for_get;
use super::*;
 use colored::*;
use futures::TryFutureExt;
use reqwest::Client;
use reqwest::{self, Url};
use serde::ser::Error;
use serde_json::json;
use utils;
 
impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn func_test(&self, auth: &Authorization) -> CheckRetVal{

        let mut ret_val = CheckRetVal::default();
        for (path, item) in &self.oas.get_paths() {
            let mut flag = false;
            for (m, op) in item.get_ops().iter() {
                create
                create_payload(&self.oas_value, op);

            }
        }

ret_val
    }
    pub async fn create_hash(&self, auth: &Authorization) -> HashMap<String, String> {
        let mut ret_val = CheckRetVal::default();
        let mut hash_set:HashSet<String> = HashSet::new();
        let mut hash_map: HashMap<String, String> = HashMap::new();
        let mut vec_param: Vec<String> = Vec::new();

        let server = &self.oas.servers();
        let mut UUID_HASH: HashMap<String, Vec<String>> = HashMap::new();
        for (path, item) in &self.oas.get_paths() {
            let mut flag = false;
            for (m, op) in item.get_ops().iter() {
                for i in op.params() {
                    let mut paramtr ;
                     paramtr = i.inner(&self.oas_value);
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase()
                        == "path".to_string()
                    {
                        hash_set.insert(i.inner(&self.oas_value).name);
                        flag = true;
                        break;
                    }
                }}}
                
                for (path, item) in &self.oas.get_paths() {
                    let mut flag = false;
                    for (_m, op) in item.get_ops().iter().filter(|(m, _)| m == &Method::GET) { 
                    // if  path param
                    for element in &hash_set{
                        let mut vec_values  = send_req(path.to_string(), &element, auth, server).await;
                        if !vec_values.is_empty(){
                            if let Some(value)= vec_values.get(0){
                                hash_map.insert(element.to_string(),value.to_string());

                            }
                        }
                    }       
                  
                             
                        
                }
                }
          
             hash_map
                

            }
        }
        
    

