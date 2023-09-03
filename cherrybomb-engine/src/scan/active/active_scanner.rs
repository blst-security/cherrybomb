use super::http_client::logs::AttackLog;
use super::http_client::*;
use crate::scan::active::http_client::auth::Authorization;
use crate::scan::active::utils::send_req;
use crate::scan::checks::*;
use crate::scan::Level;
use cherrybomb_oas::legacy::legacy_oas::OAS;
use cherrybomb_oas::legacy::path::PathItem;
use cherrybomb_oas::legacy::refs::*;
use cherrybomb_oas::legacy::schema::*;
use cherrybomb_oas::legacy::utils::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    iter,
};
use strum::IntoEnumIterator;

pub type CheckRetVal = (Vec<(ResponseData, AttackResponse)>, AttackLog);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActiveScanType {
    Full,
    Partial(Vec<ActiveChecks>),
    NonInvasive,
    OnlyTests,
}

type PayloadMap = HashMap<Vec<String>, Schema>;

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Payload {
    pub payload: Value,
    pub map: PayloadMap,
}
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Path {
    pub path_item: PathItem,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct OASMap {
    pub path: Path,
    pub payload: Payload,
}

#[derive(Default, Debug)]
pub struct ResponseData {
    pub(crate) location: String,
    pub(crate) alert_text: String,
    pub(crate) serverity: Level,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct ActiveScan<T>
where
    T: Serialize,
{
    pub oas: T,
    pub oas_value: Value,
    pub verbosity: u8,
    pub checks: Vec<ActiveChecks>,
    pub payloads: Vec<OASMap>,
    pub logs: AttackLog,
    pub path_params: HashMap<String, String>,
}

impl<T: OAS + Serialize + for<'de> Deserialize<'de>> ActiveScan<T> {
    pub fn new(oas: T, oas_value: Value) -> Result<Self, &'static str> {
        let path_params: HashMap<String, String> = HashMap::new();
        //  let path_params = Self::create_hash(&auth_p);
        let payloads = Self::payloads_generator(&oas, &oas_value);
        Ok(ActiveScan {
            oas,
            oas_value,
            checks: vec![],
            verbosity: 0,
            payloads,
            logs: AttackLog::default(),
            path_params,
        })
    }

    pub async fn run(&mut self, tp: ActiveScanType, auth: &Authorization) {
        self.path_params = Self::create_hash(self, auth).await;
        match tp {
            ActiveScanType::Full => {
                println!("{:?}",ActiveChecks::iter().collect::<Vec<ActiveChecks>>());
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

    fn payloads_generator(oas: &T, oas_value: &Value) -> Vec<OASMap> {
        let mut payloads = vec![];
        for (path, path_item) in oas.get_paths() {
            payloads.push(OASMap {
                path: (Path {
                    path_item: path_item.clone(),
                    path,
                }),
                payload: Self::build_payload(oas_value, &path_item),
            });
        }
        payloads
    }

    pub fn build_payload(oas_value: &Value, path_item: &PathItem) -> Payload {
        let mut payload = json!({});
        let mut map: PayloadMap = HashMap::new();
        for (_, op) in path_item.get_ops() {
            if let Some(req) = &op.request_body {
                for (_, med_t) in req.inner(oas_value).content {
                    let mut path = Vec::<String>::new();
                    if let Some(s_ref) = &med_t.schema {
                        let mut visited_schemes = HashSet::new();
                        path.push(Self::get_name_s_ref(s_ref, oas_value, &None));
                        payload = Self::unwind_schema(
                            oas_value,
                            s_ref,
                            &mut map,
                            &mut path,
                            &mut visited_schemes,
                        );
                    }
                }
            }
        }
        Payload { payload, map }
    }

    pub fn unwind_schema(
        oas_value: &Value,
        reference: &SchemaRef,
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
                        let ret =
                            Self::unwind_schema(oas_value, &schema, map, path, visited_schemes);
                        visited_schemes.remove(&r.param_ref);
                        ret
                    }
                    SchemaRef::Schema(schema) => {
                        map.insert(path.clone(), *schema.clone());
                        path.pop();
                        if let Some(example) = schema.example {
                            example
                        } else {
                            Self::gen_default_value(schema)
                        }
                    }
                };
            }
        } else if let Some(item_ref) = reference.items {
            // dup code from properties, probably could be improved
            payload = json!([match *item_ref {
                SchemaRef::Ref(ref r) => {
                    if visited_schemes.contains(&r.param_ref) {
                        panic!("Circular reference detected");
                    }
                    visited_schemes.insert(r.param_ref.clone());
                    let ret = Self::unwind_schema(oas_value, &item_ref, map, path, visited_schemes);
                    visited_schemes.remove(&r.param_ref);
                    ret
                }
                SchemaRef::Schema(schema) => {
                    map.insert(path.clone(), *schema.clone());
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
        let ret: Value = if let Some(data_type) = schema.schema_type {
            match data_type.as_str() {
                "string" => {
                    if let Some(num) = schema.min_length {
                        json!(iter::repeat(['B', 'L', 'S', 'T'])
                            .flatten()
                            .take(num.try_into().unwrap())
                            .collect::<String>())
                    } else {
                        json!("BLST")
                    }
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

    fn get_name_s_ref(s_ref: &SchemaRef, value: &Value, name: &Option<String>) -> String {
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
    pub async fn create_hash(&self, auth: &Authorization) -> HashMap<String, String> {
        //this function it is called once time and return a hashmap with
        //UUID as key and token as string
        let mut hash_set: HashSet<String> = HashSet::new();
        let mut hash_map: HashMap<String, String> = HashMap::new();

        let server = self.oas.servers();
        for _item in self.oas.get_paths().values() {
            for (_m, op) in _item.get_ops().iter() {
                for i in op.params() {
                    if i.inner(&self.oas_value).param_in.to_string().to_lowercase() == *"path" {
                        hash_set.insert(i.inner(&self.oas_value).name); // insert all path parameter name
                        break;
                    }
                }
            }
        }
        // dbg!(&hash_set);
        for (path, item) in &self.oas.get_paths() {
            //loop over all paths in OAS
            for (_m, _op) in item
                .get_ops()
                .iter()
                .filter(|(m, _)| m == &Method::GET)
                .filter(|(_m, op)| {
                    op.params()
                        .iter()
                        .all(|p| !p.inner(&self.oas_value).param_in.to_lowercase().eq("path"))
                })
            {
                // if  path param

                for element in &hash_set {
                    //loop over all path parameters
                    let vec_values = send_req(path.to_string(), element, auth, &server).await; // send request with parameter and return value
                    if !vec_values.is_empty() {
                        if let Some(value) = vec_values.get(0) {
                            hash_map.insert(element.to_string(), value.to_string());
                            //then add the values  into the hashmap
                        }
                    }
                }
            }
        }
        hash_map
    }
}

impl ActiveChecks {
    pub fn parse_check_list(list: Vec<String>, exclude: bool) -> Vec<ActiveChecks> {
        let mut checks = Vec::new();
        for check in list.iter() {
            let check = Self::from_string(check);
            if let Some(c) = check {
                checks.push(c);
            }
        }
        if exclude {
            let mut ex_checks: Vec<_> = Self::iter().collect();
            ex_checks.retain(|x| !checks.contains(x));
            return ex_checks;
        }
        checks
    }
}
