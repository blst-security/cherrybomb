use super::*;
mod auth;
pub use auth::*;
mod general;
pub use general::*;
mod type_checks;
pub use type_checks::*;
mod utils;
use utils::*;
mod additional_checks;
use additional_checks::*;
use strum::IntoEnumIterator;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq,Eq)]
pub enum ScanType{
    Full,
    Partial(Vec<PassiveChecks>),
}
#[derive(Debug, Clone, Serialize, Default,PartialEq,Eq)]
pub struct PassiveSwaggerScan{
    swagger:Swagger,
    swagger_value:Value,
    //alerts:Vec<iveChecks>>,
    verbosity:u8,
    passive_checks:Vec<PassiveChecks>,
}
impl PassiveSwaggerScan{
    pub fn new(swagger_value:Value)->Self{
        PassiveSwaggerScan{
            swagger:serde_json::from_value(swagger_value.clone()).unwrap(),
            swagger_value,
            passive_checks:vec![],
            verbosity:0,
        }
    }
    pub fn run(&mut self,tp:ScanType)->Vec<PassiveChecks>{
        match tp{
            ScanType::Full=>{
                for check in PassiveChecks::iter(){
                    self.passive_checks.push(self.run_check(check));
                }
            },
            ScanType::Partial(checks)=>{
                for check in checks{
                    self.passive_checks.push(self.run_check(check));
                }
            },
        };
        self.passive_checks.clone()
    }
}
