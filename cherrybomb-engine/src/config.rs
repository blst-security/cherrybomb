use clap::{Args, ValueEnum};
use serde::Deserialize;

#[derive(Default, ValueEnum, Deserialize, Clone, Debug)]
pub enum Profile {
    Info,
    #[default]
    Normal,
    Intrusive,
    Passive,
    Full,
}

#[derive(Deserialize, Debug, Default)]
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
impl Auth {
    pub fn get_auth_type(&self) -> &AuthType {
        &self.auth_type
    }
    pub fn get_auth_value(&self) -> &String {
        &self.auth_value
    }
    pub fn get_auth_scope(&self) -> &Option<String> {
        &self.auth_scope
    }
}

#[derive(ValueEnum, Deserialize, Clone, Debug)]
pub enum AuthType {
    Basic,
    Bearer,
    Header,
    Cookie,
}
