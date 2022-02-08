use super::*;
mod checks;
pub use checks::*;
pub mod passive;
pub use passive::*;
pub mod active;
pub use active::*;
mod macros;
mod print;
pub use print::*;
use colored::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq,Eq,PartialOrd,Ord)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Alert{
    pub level:Level,
    pub description:String, 
    pub location:String,
}

impl Alert{
    pub fn new(level:Level,description:&'static str,location:String)->Alert{
        Alert{level,description:description.to_string(),location}
    }
}
