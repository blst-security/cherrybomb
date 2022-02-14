use super::*;
use strum::IntoEnumIterator;
mod additional_checks;
//use additional_checks::*;
mod utils;
use utils::*;
mod flow;
use flow::*;
mod http_client;
use http_client::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActiveScanType {
    Full,
    Partial(Vec<ActiveChecks>),
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
}
impl<T: OAS + Serialize + for<'de> Deserialize<'de>> ActiveScan<T> {
    pub fn new(oas_value: Value) -> Result<Self, &'static str> {
        match serde_json::from_value::<T>(oas_value.clone()) {
            Ok(oas) => Ok(ActiveScan {
                oas,
                oas_value,
                checks: vec![],
                verbosity: 0,
            }),
            Err(e) => {
                println!("{:?}", e);
                Err("Failed at deserializing swagger value to a swagger struct, please check the swagger definition")
            }
        }
    }
    pub async fn run(&mut self, tp: ActiveScanType) {
        //->Vec<PassiveChecks>{
        match tp {
            ActiveScanType::Full => {
                for check in ActiveChecks::iter() {
                    self.checks.push(self.run_check(check).await);
                }
            }
            ActiveScanType::Partial(checks) => {
                for check in checks {
                    self.checks.push(self.run_check(check).await);
                }
            }
        };
    }
    pub fn print_to_file_string(&self) -> String {
        //let mut string = String::new();
        //string
        String::new()
    }
}
