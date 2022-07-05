use super::*;
//use mapper::digest::{ReqRes,Session};
use std::fs::OpenOptions;
use std::io::Write;
use uuid::Uuid;
// use regex::Regex;
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackLog{
    pub requests:Vec<AttackRequest>,
    pub responses:Vec<AttackResponse>,
    pub description:String,
    pub response_regexes:Vec<String>,//Regex .to_string()
    //param_links:Vec<ParamLink> from: to:
}
impl AttackLog{
    fn into_log(&self)->Vec<ReqRes>{
        let mut vec = vec![];
        for (request,response) in self.requests.iter().zip(self.responses.iter()){
            let (req_payload,req_query,path,headers) = request.params_to_payload();  
            vec.push(ReqRes{
                req_headers:request.get_headers(&headers),
                res_headers:response.headers.clone(),
                path,
                method:request.method,
                status:response.status,
                req_payload,
                res_payload:response.payload.clone(),
                req_query,
            });
        }
        vec
    }
    pub fn log(&self,log_file:&str){
        let mut log_file = OpenOptions::new().write(true).create(true).open(log_file).unwrap();
        let session = Session{
            token:Uuid::new_v4().to_string(),
            req_res:self.into_log(),
        };
        log_file.write_all(serde_json::to_string(&session).unwrap().as_bytes()).unwrap();
    }
}
