pub mod active;
pub mod checks;
pub mod macros;
pub mod passive;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialOrd, PartialEq, Eq)]
pub enum Level {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Level {
    fn default() -> Self {
        Self::Info
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Certainty {
    Passive,
    Low,
    Medium,
    High,
    Certain,
}
impl Default for Certainty {
    fn default() -> Self {
        Self::Passive
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Alert {
    pub level: Level,
    pub description: String,
    pub location: String,
    pub certainty: Certainty,
}
impl Alert {
    pub fn new(level: Level, description: &'static str, location: String) -> Alert {
        Alert {
            level,
            description: description.to_string(),
            location,
            certainty: Certainty::Passive,
        }
    }
    pub fn with_certainty(
        level: Level,
        description: String,
        location: String,
        certainty: Certainty,
    ) -> Alert {
        Alert {
            level,
            description,
            location,
            certainty,
        }
    }
}
