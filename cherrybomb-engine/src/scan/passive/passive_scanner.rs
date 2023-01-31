use crate::scan::checks::*;
use cherrybomb_oas::legacy::legacy_oas::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::IntoEnumIterator;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PassiveScanType {
    Full,
    Partial(Vec<PassiveChecks>),
}

impl Default for PassiveScanType {
    fn default() -> Self {
        Self::Full
    }
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct PassiveSwaggerScan<T>
where
    T: Serialize,
{
    pub swagger: T,
    pub swagger_value: Value,
    pub verbosity: u8,
    pub passive_checks: Vec<PassiveChecks>,
}
impl<T: OAS + Serialize + for<'de> Deserialize<'de>> PassiveSwaggerScan<T> {
    pub fn new(swagger_value: Value) -> Result<Self, &'static str> {
        match serde_json::from_value::<T>(swagger_value.clone()) {
            Ok(swagger) => Ok(PassiveSwaggerScan {
                swagger,
                swagger_value,
                passive_checks: vec![],
                verbosity: 0,
            }),
            Err(e) => {
                println!("{e:?}");
                Err("Failed at deserializing swagger value to a swagger struct, please check the swagger definition")
            }
        }
    }

    pub fn run(&mut self, tp: PassiveScanType) {
        match tp {
            PassiveScanType::Full => {
                for check in PassiveChecks::iter() {
                    self.passive_checks.push(self.run_check(check));
                }
            }
            PassiveScanType::Partial(checks) => {
                for check in checks {
                    self.passive_checks.push(self.run_check(check));
                }
            }
        };
    }
}

impl PassiveChecks {
    pub fn parse_check_list(list: Vec<String>, exclude: bool) -> Vec<PassiveChecks> {
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
