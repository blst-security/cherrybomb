//use digest::{Digest,Session,Group,Endpoint,ReqRes};
use digest::*;
use serde::{Serialize,Deserialize};

mod rule_based;
use rule_based::*;

/*fn detect_group(session:&Session,digest:&Digest)->Option<Group>{
    let eps_path:Vec<&String> = session.req_res.iter().map(|rr| &rr.path).collect();
    for group in digest.groups.clone(){
        let g_eps_path:Vec<&String> = group.endpoints.iter().map(|e| &e.path).collect();
        let mut in_group = 0;
        for p in eps_path.iter(){
            if g_eps_path.contains(&p){
                in_group+=1;
            } 
        }
        if in_group*100>=65{
            return Some(group);
        }
    }
    None
}*/
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub enum Type{
    Endpoint,
    Flow
}
impl Default for Type{
    fn default()->Self{
        Self::Endpoint
    }
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq,Default)]
pub struct Anomaly{
    session:Session,
    endpoint:Option<ReqRes>,
    r#type:Type,
}
const DEFAULT_ANOMALY_SCORE:u16 = 100;
#[derive(Debug,Clone,Serialize,Deserialize)]
pub enum RuleRCF{
    RuleBased,
    RCF
}
pub fn decide(/*way:RuleRCF,*/digest:Digest,sessions:Vec<Session>,anomaly_score:Option<u16>)->Vec<Option<Anomaly>>{
    let anomaly_score = if let Some(s)= anomaly_score {s} else {DEFAULT_ANOMALY_SCORE}; 
    let mut anomalies = vec![];
    for session in sessions{
    /*match way{
            RuleRCF::RuleBased=>{
            decide_rule_based(digest,session,anomaly_score),
        RuleRCF::RCF=>false,//decide_rcf(digest,session),
        */
        let dec = decide_rule_based(&digest,&session,anomaly_score);
        if dec.0{
            anomalies.push(Some(Anomaly{session,endpoint:dec.1,r#type:Type::Endpoint}));
        }else{
            anomalies.push(None);
        }
    }
    anomalies
}
