use super::*;
mod checks;
pub use checks::*;
pub mod passive;
pub use passive::*;
pub mod active;
pub use active::*;
mod macros;
mod print;
//use colored::*;
pub use print::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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
    Certain
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
use comfy_table::*;

use comfy_table::presets::UTF8_FULL;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
pub fn print_alerts(checks:Vec<ActiveChecks>){
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Check", "Top Severity", "Number of Alerts"]);
    for check in checks{
        let amount = check.inner().len();
        table.add_row(vec![
                      Cell::new(check.name()).add_attribute(Attribute::Bold),
                      Cell::new("Info").fg(Color::Blue),
                      Cell::new(&amount.to_string()).fg(if amount>0{Color::Red} else{ Color::Green } )
        ]);
    }
    println!("{table}");
}
pub fn print_alerts_verbose(checks:Vec<ActiveChecks>){
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Check", "Severity", "Description", "Location", "Certainty"]);
    for check in checks{
        for alert in check.inner(){
            table.add_row(vec![
                          Cell::new(check.name()).add_attribute(Attribute::Bold),
                          Cell::new(format!("{:?}",alert.level.to_string())),
                          Cell::new(alert.description).add_attribute(Attribute::Bold),
                          Cell::new(alert.location).add_attribute(Attribute::Bold),
                          Cell::new(format!("{:?}",alert.certainty))
            ]);
        }
    }
    println!("{table}");
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
    pub fn with_certainty(level: Level, description: String, location: String,certainty:Certainty) -> Alert {
        Alert {
            level,
            description,
            location,
            certainty,
        }
    }
}
