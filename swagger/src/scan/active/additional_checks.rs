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
        //println!("the haashMAp : {:?}", self.path_params);
        let values_path = self.path_params.clone();
        let mut ret_val = CheckRetVal::default();
        for (path, item) in &self.oas.get_paths() {
            let mut flag = false;
            for (m, op) in item.get_ops().iter() {
                 self.oas.servers();
                // create_payload(&self.oas_value, op);

            }
        }

ret_val
    }
 
        }
        
    

