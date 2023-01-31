use crate::scan::active::http_client::{AttackRequest, AttackResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct NetInteraction {
    req: AttackRequest,
    res: AttackResponse,
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackLog {
    log_vec: Vec<NetInteraction>,
}

impl AttackLog {
    pub fn push(&mut self, req_in: &AttackRequest, res_in: &AttackResponse, des_in: String) {
        self.log_vec.push(NetInteraction {
            req: req_in.clone(),
            res: res_in.clone(),
            description: des_in,
        })
    }
}
