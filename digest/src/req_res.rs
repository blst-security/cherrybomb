use super::*;
use std::fmt;
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ReqRes {
    pub req_headers: HashMap<String, String>,
    pub res_headers: HashMap<String, String>,
    pub path: String,
    pub method: Method,
    pub status: u16,
    pub req_payload: String,
    pub res_payload: String,
    pub req_query: String,
}
impl std::fmt::Display for ReqRes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "method:{:?}\tpath:{}\tquery:{}\nrequest headers:{:?}\nrequest_payload:{}\nstatus:{}\nresponse_headers:{:?}\nresponse_payload:{}", self.method, self.path,self.req_query,self.req_headers,self.req_payload,self.status,self.res_headers,self.res_payload)
    }
}
