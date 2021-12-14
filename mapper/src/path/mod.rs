use super::*;

mod hash;
pub use hash::*;

use serde::{Serialize,Deserialize};
//use std::collections::HashSet;

pub fn to_ext(path:String)->String{
    let end_bytes = path.find('?').unwrap_or_else(|| path.len());
    let pts:String = path[..end_bytes].to_string();
    let (path,_) = first_cycle_single(pts); 
    let path_ext = path.split('/').map(|part|{
        if part.contains("blst_param_"){
            let mut p = part.replace("blst_param_","{");
            p.push('}');
            p
        }else{
            part.to_string()
        }
    }).collect::<Vec<String>>().join("/");
    path_ext
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq,Hash)]
pub struct Path{
    pub path_ext:String,
    pub params:PayloadDescriptor,
}
impl Path{
    pub fn _cmp(self,_path:String)->bool{
        true
    }
    pub fn from_parts(path_ext:String,parts:Vec<Part>)->Self{
        let pp:Vec<&str> = path_ext.split('/').collect();
        let mut params = vec![];
        for (i,part) in parts.iter().enumerate(){
            if pp[i].starts_with("blst_param_"){
                let value = match part{
                    Part::Bool=>ValueDescriptor::Bool,
                    Part::Uuid=>ValueDescriptor::String(StringDescriptor::Uuid(4)),
                    Part::String(hm)=>search_for_patterns(hm.keys().collect()),
                    Part::Number(hm)=>search_for_patterns(hm.keys().collect()),
                };
                params.push(ParamDescriptor{
                    from:QuePay::Path,
                    name:pp[i].to_string(),
                    value,
                });
            }
        }
        let params = PayloadDescriptor{params};
        Path{
            path_ext,
            params,
        }
    }
}
