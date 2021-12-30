use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use uuid::Uuid;
pub mod hash;
pub use hash::*;
pub mod req_res;
pub use req_res::*;
pub mod session;
pub use session::*;
pub mod utils;
pub use utils::*;
pub mod ep;
pub use ep::*;
pub mod group;
pub use group::*;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Digest {
    pub path_hash:HashMap<String,u32>,
    pub ep_hash: Vec<EndpointHash>,
    pub link_hash: LinksHash,
    pub eps: Vec<Endpoint>,
    pub groups: Vec<Group>,
}
