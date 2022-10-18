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
    
    pub async fn check_broken_object(&self, auth: &Authorization) -> CheckRetVal {
        let mut ret_val = CheckRetVal::default();
        let mut vec_param: Vec<RequestParameter> = Vec::new();

        let server = &self.oas.servers();
       // let mut param_object;
       let mut UUID_HASH:HashMap<(Path,String),String> = HashMap::new();
       for (path, item) in &self.oas.get_paths() {
        let mut flag = false;
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
               let val = i.schema.unwrap_or_default().inner(&self.oas_value).items.unwrap_or_default();
               //println!("items, {:?}", val);
                 println!("compo {:?}", val.inner(&self.oas_value).properties);
               //let compo = val.inner(&self.oas_value).items.unwrap_or_default().inner(&self.oas_value);
               //println!("COMPO {:?}", compo);

            }

              }
             // if let Some(value) = data_resp {
            //     let param_obj = value.inner(&self.oas_value).content.unwrap().into_values();
            //     for i in param_obj {
            //         println!("SCHEMA {:?}", i.schema.unwrap().inner(&self.oas_value).required);
            //     }
           // }
            }
        }
    }

       return ret_val;
        }
    }
       
       
    


