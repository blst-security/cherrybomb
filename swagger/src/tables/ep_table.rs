use super::*;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EpForTable{
    path:String,
    //urls
    servers:Vec<String>,
    ops:Vec<Method>,
    query_params:Vec<String>,
    headers_params:Vec<String>,
    req_body_params:Vec<String>,
    res_params:Vec<String>,
    statuses:Vec<String>,
}
impl EpForTable{
    pub fn from_oas_path(path:&str,item:&PathItem,value:&Value)->Self{
        let ops1 = item.get_ops(); 
        //,req_body_params,res_params
        let (mut query_params,mut headers_params):(Vec<String>,Vec<String>) =(vec![],vec![]);
        for (_,op) in ops1.iter(){
            let q:Vec<String> = op.params().iter().filter_map(|param|{
                let param = param.inner(value);
                match param.from(){
                    QuePay::Query=>Some(param.name),
                    _=>None,
                } 
            }).collect();
            let h:Vec<String> = op.params().iter().filter_map(|param|{
                let param = param.inner(value);
                match param.from(){
                    QuePay::Headers=>Some(param.name),
                    _=>None,
                } 
            }).collect();
            query_params.extend(q);
            headers_params.extend(h);
        }
        EpForTable{
            path:path.to_string(),
            servers:item.servers.as_ref().unwrap_or(&vec![]).iter().map(|s| s.url.clone()).collect(),
            ops:ops1.iter().map(|(m,_)| m).cloned().collect(),
            query_params,
            headers_params,
            statuses:ops1.iter().map(|(_,op)| op.responses.as_ref().unwrap_or(&HashMap::new()).iter().map(|(s,_)| s).cloned().collect::<Vec<String>>()).flatten().collect(),
            ..Self::default()
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EpTable{
    eps:Vec<EpForTable>,
    servers:Vec<String>,
}
impl EpTable{
    pub fn new<T>(oas:T)->Self
    where T:OAS+Clone+Serialize{
        let val = serde_json::to_value(&oas).unwrap();
        let eps:Vec<EpForTable> = oas.get_paths().iter().map(|(path,item)| EpForTable::from_oas_path(path,item,&val)).collect();
        println!("{:?}",eps[0].clone());
        EpTable{
            eps,
            servers:oas.servers().as_ref().unwrap_or(&vec![]).iter().map(|s| s.url.clone()).collect(),
        }
    }
}
