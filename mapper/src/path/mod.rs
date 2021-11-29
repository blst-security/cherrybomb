use super::*;

mod hash;
pub use hash::*;

use serde::{Serialize,Deserialize};
//use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Path{
    path_ext:String,
    params:PayloadDescriptor,
}
