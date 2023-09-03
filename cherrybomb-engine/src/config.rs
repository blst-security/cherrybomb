use clap::{Args, ValueEnum};
use serde::Deserialize;
use crate::Authorization;
use crate::scan::active::http_client::auth::Custom;
use crate::scan::active::http_client::QuePay;

#[derive(Default, ValueEnum, Deserialize, Clone, Debug)]
pub enum Profile {
    Info,
    #[default]
    Normal,
    Active,
    Passive,
    Full,
    OWASP,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(default)]
pub struct Config {
    pub file: std::path::PathBuf,
    pub verbosity: Verbosity,
    pub profile: Profile,
    pub passive_include: Vec<String>,
    pub passive_exclude: Vec<String>,
    pub active_include: Vec<String>,
    pub active_exclude: Vec<String>,
    pub servers_override: Vec<String>,
    pub security: Vec<Auth>,
    pub ignore_tls_errors: bool,
    pub no_color: bool,
    pub active_checks: Vec<String>,
    pub passive_checks: Vec<String>,
}
impl Config {
    pub fn update_checks_passive(&mut self, mut vec_checks: Vec<String>) {
        //get a list of passive checks and remove exclude
        vec_checks.retain(|check| !self.passive_exclude.contains(check));
        self.passive_checks = vec_checks;
    }
    pub fn update_checks_active(&mut self, mut vec_checks: Vec<String>) {
        //get a list of active checks and remove exclude
        vec_checks.retain(|check| !self.active_exclude.contains(check));
        self.active_checks = vec_checks;
    }
}

impl Config{
    pub fn get_auth(&self) -> Authorization{
        if !self.security.is_empty(){
            self.security[0].to_auth_legacy()
        } else {
            Authorization::None
        }
    }
}

#[derive(ValueEnum, Deserialize, Clone, Debug, Default, PartialOrd, PartialEq)]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
    Debug,
}

#[derive(ValueEnum, Deserialize, Clone, Debug)]
pub enum AuthType {
    Basic,
    Bearer,
    Header,
    Cookie,
}

#[derive(Args, Deserialize, Debug, Clone)]
pub struct Auth {
    /// Authentication type
    #[arg(long = "type", value_enum)]
    auth_type: AuthType,
    /// Entire String to use as the value
    /// (header-name: header-value / cookie-name: cookie-value / bearer-token)
    #[arg(long = "value")]
    auth_value: String,
    /// Name of the scope matching the security scheme
    #[arg(long = "scope")]
    auth_scope: Option<String>,
}
impl Auth{
    pub fn to_auth_legacy(&self) -> Authorization{
        match self.auth_type{
            AuthType::Basic => {
                Authorization::Custom(Custom{
                    dm:QuePay::Headers,
                    name:String::from("Authorization"),
                    value:format!("Basic {}",self.auth_value),
                })
            },
            AuthType::Bearer =>{
                Authorization::Custom(Custom{
                    dm:QuePay::Headers,
                    name:String::from("Authorization"),
                    value:format!("Bearer {}",self.auth_value),
                })
            }
            AuthType::Header | AuthType::Cookie=> {
                let vv = self.auth_value.split(':').collect::<Vec<&str>>();
                if vv.len()!=2{
                    panic!("Auth is not configured properly:\n{}",self.auth_value);
                }
                Authorization::Custom(Custom{
                    dm:QuePay::Headers,
                    name:vv[0].to_owned(),
                    value:vv[1].to_owned(),
                })
            }
        }
    }
}
