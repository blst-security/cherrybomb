use clap::{Args, ValueEnum};
use serde::Deserialize;

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

#[derive(ValueEnum, Deserialize, Clone, Debug, Default, PartialOrd, PartialEq)]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
    Debug,
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

#[derive(ValueEnum, Deserialize, Clone, Debug)]
pub enum AuthType {
    Basic,
    Bearer,
    Header,
    Cookie,
}
