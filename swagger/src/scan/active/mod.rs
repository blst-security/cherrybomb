use super::*;
use strum::IntoEnumIterator;

mod additional_checks;
mod response_checks;
mod flow;
mod http_client;
mod logs;
mod utils;


use http_client::*;
pub use http_client::Authorization;
pub use logs::*;
use serde_json::json;
use std::{iter, collections::HashSet};


type CheckRetVal = (Vec<(ResponseData, AttackResponse)>, AttackLog);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActiveScanType {
    Full,
    Partial(Vec<ActiveChecks>),
    NonInvasive,
    OnlyTests,
}


type PayloadMap = HashMap<Vec<String>, Schema>;

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Payload {
    pub payload: Value,
    pub map: PayloadMap,
}
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Path{
    pub path_item: PathItem,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
struct OASMap {
    pub path: Path,
    pub payload: Payload,
}

#[derive(Default)]
pub struct ResponseData {
    location: String,
    alert_text: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct ActiveScan<T>
    where
        T: Serialize,
{
    oas: T,
    oas_value: Value,
    verbosity: u8,
    pub checks: Vec<ActiveChecks>,
    payloads: Vec<OASMap>,
    logs: AttackLog,

}

impl<T: OAS + Serialize + for<'de> Deserialize<'de>> ActiveScan<T> {
    pub fn new(oas_value: Value) -> Result<Self, &'static str> {
        let oas = match serde_json::from_value::<T>(oas_value.clone()) {
            Ok(oas) => oas,
            Err(e) => {
                println!("{:?}", e);
                return Err("Failed at deserializing swagger value to a swagger struct, please check the swagger definition");
            }
        };
        let payloads = Self::payloads_generator(&oas, &oas_value);
        Ok(ActiveScan {
            oas,
            oas_value,
            checks: vec![],
            verbosity: 0,
            payloads,
            logs: AttackLog::default(),
        })
    }
    pub async fn run(&mut self, tp: ActiveScanType, auth: &Authorization) {
        match tp {
            ActiveScanType::Full => {
                for check in ActiveChecks::iter() {
                    self.checks.push(self.run_check(check, auth).await);
                }
            }
            ActiveScanType::NonInvasive => {
                for check in ActiveChecks::iter() {
                    self.checks.push(self.run_check(check, auth).await);
                }
            }
            ActiveScanType::OnlyTests => {
                for check in ActiveChecks::iter() {
                    self.checks.push(self.run_check(check, auth).await);
                }
            }
            ActiveScanType::Partial(checks) => {
                for check in checks {
                    self.checks.push(self.run_check(check, auth).await);
                }
            }
        };
    }
    pub fn print(&self, verbosity: u8) {
        // println!("{:?}", self.checks);
        dbg!(&self.checks);
        match verbosity { //TODO support verbosity
            0 => {
                // print_alerts_verbose(self.checks.clone());
            }
            1 => {
                // print_alerts(self.checks.clone());
            }
            _ => (),
        }
    }
    pub fn print_to_file_string(&self) -> String {
        String::new()
    }


    fn payloads_generator(oas: &T, oas_value: &Value) -> Vec<OASMap> {
        let mut payloads = vec![];
        for (path, path_item) in oas.get_paths() {
            payloads.push(
                OASMap { 
                    path: (Path{
                        path_item: path_item.clone(),
                        path}),
                    payload: 
                        Self::build_payload(oas_value, &path_item)
                    }
            );
        }
        payloads
    }


    pub fn build_payload(oas_value: &Value, path_item: &PathItem) -> Payload{
        let mut payload = json!({});
        let mut map: PayloadMap = HashMap::new();
        for (_, op) in path_item.get_ops() {
            if let Some(req) = &op.request_body {
                for (_, med_t) in req.inner(oas_value).content {
                    let mut path = Vec::<String>::new();
                    if let Some(s_ref) = &med_t.schema {
                        let mut visited_schemes = HashSet::new();
                        path.push(Self::get_name_s_ref(s_ref, oas_value, &None));
                        payload = Self::unwind_schema(oas_value, s_ref, &mut map, &mut path, &mut visited_schemes);
                    }
                }
            }
        }
        Payload{
            payload,
            map,
        }
    }


    pub fn unwind_schema(
        oas_value: &Value, reference: &SchemaRef,
        map: &mut HashMap<Vec<String>, Schema>,
        path: &mut Vec<String>,
        visited_schemes: &mut HashSet<String>,
        ) -> Value {
        let mut payload = json!({});
        let reference = reference.inner(oas_value);
        if let Some(example) = reference.example {
            payload = example;
        } else if let Some(prop_map) = reference.properties {
            for (name, schema) in prop_map {
                path.push(name.clone());
                payload[&name] = match schema {
                    SchemaRef::Ref(ref r) => {
                        if visited_schemes.contains(&r.param_ref) {
                            panic!("Circular reference detected");
                        }
                        visited_schemes.insert(r.param_ref.clone());
                        let ret = Self::unwind_schema(oas_value, &schema, map, path,visited_schemes);
                        visited_schemes.remove(&r.param_ref);
                        ret
                    }
                    SchemaRef::Schema(schema) => {
                        map.insert(
                            path.clone(),
                            *schema.clone(),
                        );
                        path.pop();
                        if let Some(example) = schema.example {
                            example
                        } else {
                            Self::gen_default_value(schema)
                        }
                    }
                };
            }
        } else if let Some(item_ref) = reference.items { // dup code from properties, probably could be improved
            payload = json!([
                match *item_ref {
                    SchemaRef::Ref(ref r) => {
                        if visited_schemes.contains(&r.param_ref) {
                            panic!("Circular reference detected");
                        }
                        visited_schemes.insert(r.param_ref.clone());
                        let ret = Self::unwind_schema(oas_value, &item_ref, map, path,visited_schemes);
                        visited_schemes.remove(&r.param_ref);
                        ret
                    }
                    SchemaRef::Schema(schema) => {
                        map.insert(
                            path.clone(),
                            *schema.clone(),
                        );
                        path.pop();
                        if let Some(example) = schema.example {
                            example
                        } else {
                            Self::gen_default_value(schema)
                        }
                    }
                }]);
        }
        payload
    }

    pub fn gen_default_value(schema: Box<Schema>) -> Value {
        let ret: Value =
            if let Some(data_type) = schema.schema_type {
                match data_type.as_str() {
                    "string" => {
                        if let Some(num) = schema.min_length {
                            json!(iter::repeat(['B','L','S','T']).
                            flatten().
                            take(num.try_into().unwrap()).
                            collect::<String>())
                        } else { json!("BLST") }
                    }
                    "integer" => {
                        if let Some(num) = schema.minimum {
                            json!(num)
                        } else {
                            json!(5usize)
                        }
                    }
                    "boolean" => {
                        json!(false)
                    }
                    _ => {
                        json!({})
                    }
                }
            } else {
                json!({})
            };
        ret
    }

    pub fn get_name_s_ref(s_ref: &SchemaRef, value: &Value, name: &Option<String>) -> String {
        let schema = s_ref.inner(value);
        if let Some(ref t) = schema.title {
            t.to_string()
        } else if let SchemaRef::Ref(r) = s_ref {
            r.param_ref.split('/').last().unwrap().to_string()
        } else if let Some(n) = name {
            n.to_string()
        } else {
            String::new()
        }
    }
}

impl ActiveChecks {
    pub fn parse_check_list(list: Vec<String>, exclude: bool) -> Vec<ActiveChecks>{
        let mut checks = Vec::new();
        for check in list.iter(){
            let check = Self::from_string(check);
            if let Some(c) = check {checks.push(c);}
        }
        if exclude{
           let mut ex_checks: Vec<_> = Self::iter().collect();
           ex_checks.retain(|x| !checks.contains(x));
           return ex_checks
        }
        checks
    }
}
