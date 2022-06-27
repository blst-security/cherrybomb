use super::*;
use strum::IntoEnumIterator;

mod additional_checks;
mod response_checks;
mod utils;
mod flow;
mod http_client;
mod logs;


use http_client::*;
pub use http_client::Authorization;
use utils::*;
pub use logs::*;
use serde_json::json;
use std::iter;


type CheckRet = (Vec<(ResponseData, AttackResponse)>,AttackLog);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActiveScanType {
    Full,
    Partial(Vec<ActiveChecks>),
    NonInvasive,
    OnlyTests,
}

type OASMap = HashMap<Vec<String>, Schema>;
type StaticThingy = HashMap<String, (Value, OASMap)>;

#[derive(Default)]
pub struct ResponseData{
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
    checks: Vec<ActiveChecks>,
    static_props: StaticThingy,
    logs: AttackLog,
}

impl<T: OAS + Serialize + for<'de> Deserialize<'de>> ActiveScan<T> {
    pub fn new(oas_value: Value) -> Result<Self, &'static str> {
        //TODO
        // todo!();
        let oas = match serde_json::from_value::<T>(oas_value.clone()) {
            Ok(oas) => oas,
            Err(e) => {
                println!("{:?}", e);
                return Err("Failed at deserializing swagger value to a swagger struct, please check the swagger definition");
            }
        };
        let static_props = Self::static_thingy_creator(&oas,&oas_value);
        Ok(ActiveScan {
            oas,
            oas_value,
            checks: vec![],
            verbosity: 0,
            static_props,
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
        match verbosity {
            0 => {
                //print_checks_table(&self.checks);
                println!("{:?}",self.checks);
                // print_attack_alerts_table(&self.checks);
            }
            1 => {
                //print_checks_table(&self.checks);
            }
            2 => print_failed_checks_table(&self.checks),
            _ => (),
        }
    }
    pub fn print_to_file_string(&self) -> String {
        String::new()
    }

    pub fn static_thingy_creator(oas: &T, oas_value : &Value) -> StaticThingy {
        let mut ret_val = StaticThingy::new();
        for (path, item) in oas.get_paths() {
            let (map, payload)
                = Self::build_payload( oas_value, &item);
            ret_val.insert(path.clone(), (payload, map));
        }
        ret_val
    }

    pub fn build_payload(oas_value: &Value,path_item: &PathItem) -> (HashMap<Vec<String>, Schema>, Value) {
        let mut payload = json!({});
        let mut map: HashMap<Vec<String>, Schema> = HashMap::new();
        for (_, op) in path_item.get_ops() {
            if let Some(req) = &op.request_body {
                for (_, med_t) in req.inner(oas_value).content {
                    let mut path = Vec::<String>::new();
                    if let Some(s_ref) = &med_t.schema {
                        path.push(Self::get_name_s_ref(s_ref, oas_value, &None));
                        payload = Self::unwind_scheme(oas_value, s_ref, &mut map, &mut path);
                    }
                }
            }
        }
        (map, payload)
    }

    pub fn unwind_scheme( oas_value: &Value, reference: &SchemaRef,
                         map: &mut HashMap<Vec<String>, Schema>,
                         path: &mut Vec<String>) -> Value {
        let mut payload = json!({});
        let reference = reference.inner(oas_value);
        if let Some(example) = reference.example {
            todo!();
        }
        if let Some(prop_map) = reference.properties {
            for (name, schema) in prop_map {
                path.push(name.clone());
                payload[&name] = match schema {
                    SchemaRef::Ref(_) => {
                        Self::unwind_scheme(oas_value, &schema, map, path)
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
        } else if let Some(item_map) = reference.items {
            // todo!();
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
