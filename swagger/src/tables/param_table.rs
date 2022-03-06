use super::*;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct ParamForTableKey{
    name:String,
    #[serde(rename = "type")]
    param_type:String,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamForTableValue{
    eps:HashSet<String>,
    dms:HashSet<QuePay>,
    statuses:HashSet<String>,
    parents:HashSet<String>,
    children:HashSet<String>,
    max:Option<i64>,
    min:Option<i64>,
    //default:Option<SchemaStrInt>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamForTable{
    name:String,
    //probably will become an Enum
    #[serde(rename = "type")]
    param_type:String,
    statuses:Vec<String>,
    //probably will become an Enum
    //from:String,
    dms:Vec<QuePay>,
    eps:Vec<String>,
    parents:Vec<String>,
    children:Vec<String>,
    max:Option<i64>,
    min:Option<i64>,
    //default:Option<SchemaStrInt>,
}
impl fmt::Display for ParamForTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max = if let Some(m) = self.max { m } else { i64::MAX };
        let min = if let Some(m) = self.min { m } else { i64::MIN };
        write!(f, "{}\t|{}\t|{:?}\t|{:?}\t|{:?}\t|{:?}\t|{:?}\t|{}\t|{}",self.name,self.param_type,self.statuses,self.dms,self.eps,self.parents,self.children,max,min)
    }
}
impl ParamForTable{
    pub fn from_hash(hash:HashMap<ParamForTableKey,ParamForTableValue>)->Vec<ParamForTable>{
        let mut vec = vec![];
        for (key,value) in hash{
            vec.push(ParamForTable{
                name:key.name,
                param_type:key.param_type,
                statuses:value.statuses.iter().cloned().collect(),
                dms:value.dms.iter().cloned().collect(),
                eps:value.eps.iter().cloned().collect(),
                parents:value.parents.iter().cloned().collect(),
                children:value.children.iter().cloned().collect(),
                max:value.max,
                min:value.min,
            });  
        }
        vec
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamTable{
    info:Info,
    servers:Vec<String>,
    params:Vec<ParamForTable>,
    eps:Vec<String>,
}
impl ParamTable{
    pub fn print(&self){
        //println!("info:{:?}",self.info);
        //println!("urls:{:?}",self.servers);
        //println!("eps:{:?}",self.eps);
        for param in &self.params{
            println!("{}",param);
        }
    }
    pub fn new<T>(oas:T)->Self
    where T:OAS+Clone+Serialize{
        ParamTable{
            info:oas.info(), 
            servers:oas.servers().unwrap_or(vec![]).iter().map(|s| s.url.clone()).collect(),
            params:Self::get_params(&oas,&serde_json::to_value(oas.clone()).unwrap()),
            eps:oas.get_paths().iter().map(|(p,i)| p).cloned().collect(),
        }
    }
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
    fn get_min_max(schema:&Schema,tp:&str)->(Option<i64>,Option<i64>){
        match tp{
            _=>(None,None),
        }
    }
    fn get_params_rec(params:&mut HashMap<ParamForTableKey,ParamForTableValue>,schema_ref:SchemaRef,path:String,parent:Option<String>,dm:QuePay,status:Option<String>,name:Option<String>,value:&Value){
        let mut children = vec![];
        let schema = schema_ref.inner(value); 
        let name = if let Some(ref t) = schema.title{ 
            t.to_string()
        } else if let SchemaRef::Ref(r) = schema_ref{
            r.param_ref.split("/").last().unwrap().to_string()
        }else if let Some(n) = name{
            n
        }else{
            String::new()
        };
        for s in Self::get_all_possible_schemas(&schema){
            if let Some(t) = s.inner(value).title{
                children.push(t);
                Self::get_params_rec(params,s,path.clone(),Some(name.clone()),dm,status.clone(),None,value); 
            }
        }
        for (n,prop) in Self::get_props(&schema){
            Self::get_params_rec(params,prop,path.clone(),Some(name.clone()),dm,status.clone(),Some(n),value);
        }
        let tp = if let Some(ref tp) = schema.schema_type{
            tp.to_string()
        }else{
            String::new()
        };
        let key = ParamForTableKey{name,param_type:tp.clone()};
        let val = params.entry(key).or_insert(ParamForTableValue::default());
        val.eps.insert(path);
        val.dms.insert(dm);
        if let Some(st) = status{
            val.statuses.insert(st);
        }
        if let Some(p) = parent{
            val.parents.insert(p);
        }
        val.children.extend(children);
        let (min,max) = Self::get_min_max(&schema,&tp);
        if val.min>min{
            val.min = min;
        }
        if val.max < max{
            val.max = max;
        }
    }
    pub fn get_params<T>(oas:&T,value:&Value)->Vec<ParamForTable>
    where T:OAS{
        let mut params:HashMap<ParamForTableKey,ParamForTableValue> = HashMap::new();
        for (path,item) in oas.get_paths(){
            for (_,op) in item.get_ops(){
                if let Some(b) = &op.request_body{
                    for (_,m_t) in b.inner(value).content{
                        if let Some(schema) = m_t.schema{
                            Self::get_params_rec(&mut params,schema,path.clone(),None,QuePay::Payload,None,None,value);
                        }
                    }
                }
                for (status, payload) in op.responses() {
                    if let Some(c) = payload.inner(value).content {
                        for (_,m_t) in c{
                            if let Some(schema) = m_t.schema{
                                Self::get_params_rec(&mut params,schema,path.clone(),None,QuePay::Response,Some(status.clone()),None,value);
                            }
                        }
                    }
                }
            }
            let params1 = if let Some(p) = item.parameters { p } else { vec![] };
            for param in params1{
                let param = param.inner(value);
                if let Some(schema) = param.schema.clone(){
                    Self::get_params_rec(&mut params,schema,path.clone(),None,param.from(),None,None,value);
                } 
            }
        }
        ParamForTable::from_hash(params)
    }
}
