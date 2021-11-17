

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;


mod actions;
pub use actions::*;
