use super::*;
mod checks;
pub use checks::*;
mod passive;
pub use passive::*;
mod macros;
mod print;
pub use print::*;
use colored::*;

pub trait PassiveScanRule{
    fn scan(&self) -> Vec<Alert>;
}
/*
pub trait ActiveScanRule{
    fn scan(&self) -> Vec<Alert>;
}*/
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq,Eq)]
pub enum Level{
    Info,
    Low,
    Medium,
    High,
    Critical
}
impl Default for Level {
    fn default() -> Self {
        Self::Info
    }
}
pub trait ScanRule{}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Alert{//<T>{
    pub level:Level,
    pub description:String, 
    pub location:String,
}

impl Alert{
    pub fn new(level:Level,description:&'static str,location:String)->Alert{
        Alert{level,description:description.to_string(),location}
    }
}
