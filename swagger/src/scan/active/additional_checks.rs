use super::utils::create_payload_for_get;
use super::*;
use colored::*;
use reqwest;
use reqwest::Client;
use serde::ser::Error;
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
    
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param: Vec<RequestParameter> = Vec::new();

        let server = &self.oas.servers();
       // let mut param_object;
       let mut UUID_HASH:HashMap<(Path,String),String> = HashMap::new();
       for (path, item) in &self.oas.get_paths() {
        let mut flag = false;
        let mut flag2= false;
        for (m, op) in item.get_ops().iter()
        .filter(|(m, _)| m == &Method::GET ){
        for i in op.params() {
            if i.inner(&self.oas_value).param_in.to_string().to_lowercase() == "path".to_string() {//|| i.inner(&self.oas_value).param_in.to_string().to_lowercase() == "query" 
                flag= true; 
                break;
            }
            println!()
        }
        if !flag {
            let responses = op.responses();
          //  dbg!("responses {:?}", &responses);
            let data_resp = responses.get(&"200".to_string());
            //println!("dataaaa {:?}", data_resp);
             if let Some(v) = data_resp {
               // let values = v.inner(&self.oas_value).content;
               let values = v.inner(&self.oas_value).content.unwrap_or_default().into_values();
               for i in values {
             //  println!("HHHHH {:?}", i.schema);
             if i.schema.as_ref().unwrap().inner(&self.oas_value).schema_type.unwrap_or_default().to_string() == "array".to_string(){              
               let val = i.schema.unwrap().inner(&self.oas_value).items.unwrap_or_default();
               //println!("items, {:?}", val);
                // println!("compo {:?}", val.inner(&self.oas_value).properties);
               //let compo = val.inner(&self.oas_value).items.unwrap_or_default().inner(&self.oas_value);
               //println!("COMPO {:?}", compo);
               let var_name:Vec<String> = val.inner(&self.oas_value).properties.unwrap().keys().cloned().collect();
               let mut liste_of_values :Vec<String> = Vec::new();
               for values in var_name {
                println!("values: {:?}", values);
                if values.contains(&"id".to_string()){
                  liste_of_values.push(values.clone());
                  flag2 = true;
                }
               }
                if flag2{
                  let url1 = format!("http://localhost:8000/{:?}", path);
                  let r = reqwest::get(&url1).await;  
                  match r {
                    Ok(v)=> { println!("heyy thisis the response {:?}", v);
                  },
                  Err(r)=>{println!("errrror: {:?}", r);}
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
//



 
                //
            }

              }
          
            }
        }
    }

       return ret_val;
        }
    }
       
       
    


