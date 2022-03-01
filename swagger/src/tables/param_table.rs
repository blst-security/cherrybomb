use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct ParamForTableKey{
    name:String,
    #[serde(rename = "type")]
    param_type:String,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamForTableValue{
    eps:Vec<String>,
    dms:Vec<QuePay>,
    statuses:Vec<String>,
    parents:Vec<String>,
    children:Vec<String>,
    max:Option<i64>,
    min:Option<i64>,
    default:Option<SchemaStrInt>,
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
impl ParamForTable{
    pub fn from_hash(hash:HashMap<ParamForTableKey,ParamForTableValue>)->Vec<ParamForTable>{
        vec![]
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
    pub fn new<T>(oas:T)->Self
    where T:OAS+Clone+Serialize{
        ParamTable{
            info:oas.info(), 
            servers:oas.servers().unwrap_or(vec![]).iter().map(|s| s.url.clone()).collect(),
            params:Self::get_params(&oas,&serde_json::to_value(oas.clone()).unwrap()),
            eps:oas.get_paths().iter().map(|(p,i)| p).cloned().collect(),
        }
    }
    fn get_params_rec(params:HashMap<ParamForTableKey,ParamForTableValue>,schema:SchemaRef,path:String,parent:Option<String>)->HashMap<ParamForTableKey,ParamForTableValue>{
        let mut params = HashMap::new();
        params
    }
    pub fn get_params<T>(oas:&T,value:&Value)->Vec<ParamForTable>
    where T:OAS{
        let mut params:HashMap<ParamForTableKey,ParamForTableValue> = HashMap::new();
        for (path,item) in oas.get_paths(){
            for (_,op) in item.get_ops(){
                if let Some(b) = &op.request_body{
                    for (_,m_t) in b.inner(value).content{
                        if let Some(schema) = m_t.schema{
                            params = Self::get_params_rec(params,schema,path.clone(),None);
                        }
                    }
                }
                for (status, payload) in op.responses() {
                    if let Some(c) = payload.inner(value).content {
                        for (_,m_t) in c{
                            if let Some(schema) = m_t.schema{
                                params = Self::get_params_rec(params,schema,path.clone(),None);
                            }
                        }
                    }
                }
                // parameter rec needs to be impld
            }
        }
        ParamForTable::from_hash(params)
    }
}
