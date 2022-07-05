use serde::{Deserialize, Serialize};
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

mod actions;
pub use actions::*;
mod utils;
pub use utils::*;
mod config;
pub use config::*;
//mod auth;
//pub use auth::*;
