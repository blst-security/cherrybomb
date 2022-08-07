use super::*;
mod auth;
pub use auth::*;
mod general;
pub use general::*;
mod type_checks;
pub use type_checks::*;
mod utils;
pub use utils::*;
mod additional_checks;
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
    swagger: T,
    swagger_value: Value,
    //alerts:Vec<iveChecks>>,
    verbosity: u8,
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
                println!("{:?}", e);
                Err("Failed at deserializing swagger value to a swagger struct, please check the swagger definition")
            }
        }
    }
    pub fn run(&mut self, tp: PassiveScanType) {
        //->Vec<PassiveChecks>{
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
        //self.passive_checks.clone()
    }
    pub fn print(&self, verbosity: u8) {
        match verbosity {
            0 => {
                print_checks_table(&self.passive_checks);
                print_alerts_table(&self.passive_checks);
            }
            1 => print_checks_table(&self.passive_checks),
            2 => print_failed_checks_table(&self.passive_checks),
            _ => (),
        }
    }
    pub fn print_to_file_string(&self) -> String {
        let mut string = String::new();
        for check in &self.passive_checks {
            string.push_str(&format!(
                "CHECK: {:?}\tALERTS:{}\tTOP SEVERITY:{:?}\n",
                check.name(),
                check.inner().len(),
                check.top_severity()
            ));
            for alert in check.inner() {
                string.push_str(&format!(
                    "LEVEL:{:?}\tLOCATION:{:?}\tDESCRIPTION:{:?}\n",
                    alert.level, alert.location, alert.description
                ));
            }
        }
        string
    }
}
impl PassiveChecks{
    pub fn parse_check_list(list: Vec<String>, exclude: bool) -> Vec<PassiveChecks>{
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