use super::param::*;
use super::utils::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Ep {
    pub path: String,
    pub method: Method,
    pub path_params: Vec<Param>,
    pub req_payload_params: Option<Param>,
    pub req_payload_type: Option<String>,
    pub res_payload_params: HashMap<String, Param>,
    pub servers: Vec<String>,
}
/*
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq,Copy)]
struct R{

}
impl PassiveScanRule for R{
    fn scan(&self)->Vec<Alert>{
        vec![]
    }
}
impl Ep{
    pub fn scan_rule<T>(&self,rule:T)->Vec<Alert>
    where T:PassiveScanRule{
        rule.scan()
    }
    pub fn scan(&self)->Vec<Alert>{
        self.scan_rule(R{})
    }
}*/
