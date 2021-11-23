use super::*;
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Session {
    pub req_res: Vec<ReqRes>,
    pub token: String,
}
impl Session {
    pub fn new(req_res: Vec<ReqRes>, token: String) -> Session {
        Session { req_res, token }
    }
}
