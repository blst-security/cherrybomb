use super::*;
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]
pub struct ReqRes{
    pub req_headers:HashMap<String,String>,
    pub res_headers:HashMap<String,String>,
    pub path:String,
    pub method:Method,
    pub status:u16,
    pub req_payload:String,
    pub res_payload:String,
    pub req_query:String,
}
