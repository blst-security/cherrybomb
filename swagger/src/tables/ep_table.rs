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
    fn get_all_possible_schemas(schema:&Schema)->Vec<SchemaRef>{
        let mut schemas = vec![];
        if let Some(items) = schema.items.clone() {
            schemas.push(*items);
        }
        if let Some(any) = schema.any_of.clone() {
            schemas.extend(any);
        }
        if let Some(all) = schema.all_of.clone() {
            schemas.extend(all);
        }
        if let Some(one) = schema.one_of.clone() {
            schemas.extend(one);
        }
        schemas
    }
    fn get_props(schema:&Schema)->HashMap<String,SchemaRef>{
        if let Some(props) = schema.properties.clone() {
            props
        }else{
            HashMap::new()
        }
    }
    fn get_name_s_ref(s_ref:&SchemaRef,value:&Value,name:&Option<String>)->String{
        let schema = s_ref.inner(value); 
        if let Some(ref t) = schema.title{ 
            t.to_string()
        } else if let SchemaRef::Ref(r) = s_ref{
            r.param_ref.split('/').last().unwrap().to_string()
        }else if let Some(n) = name{
            n.to_string()
        }else{
            String::new()
        }
    }
    fn schema_rec(params:&mut Vec<String>,schema_ref:&SchemaRef,value:&Value,name_f:Option<String>)->Vec<String>{
        let schema = schema_ref.inner(value); 
        for s in Self::get_all_possible_schemas(&schema){
            let n = Self::get_name_s_ref(schema_ref,value,&name_f);
            Self::schema_rec(params,&s,value,Some(n)); 
        }
        for (n,prop) in Self::get_props(&schema){
            Self::schema_rec(params,&prop,value,Some(n));
        }
        params.to_vec()
    }
    pub fn from_oas_path(path:&str,item:&PathItem,value:&Value)->Self{
        let ops1 = item.get_ops(); 
        //,req_body_params,res_params
        let (mut query_params,mut headers_params,mut req_body_params, mut res_params):(Vec<String>,Vec<String>,Vec<String>,Vec<String>) =(vec![],vec![],vec![],vec![]);
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
            let req= if let Some(b) = &op.request_body{
                let mut params = vec![];
                for m_t in b.inner(value).content.values(){
                    if let Some(schema) = &m_t.schema{
                        Self::schema_rec(&mut params,schema,value,None);
                    }
                }
                params.to_vec()
            }else{
                vec![]
            };
            let res:Vec<String>= op.responses().iter().map(|(_,payload)|{
                let mut params = vec![];
                if let Some(c) = &payload.inner(value).content {
                    for m_t in c.values(){
                        if let Some(schema) = &m_t.schema{
                            Self::schema_rec(&mut params,schema,value,None);
                        }
                    }
                }
                params
            }).flatten().collect();
            query_params.extend(q);
            headers_params.extend(h);
            req_body_params.extend(req);
            res_params.extend(res);
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
        for i in 0..10{
            println!("{:?}",&eps[i]);
        }
        EpTable{
            eps,
            servers:oas.servers().as_ref().unwrap_or(&vec![]).iter().map(|s| s.url.clone()).collect(),
        }
    }
}
