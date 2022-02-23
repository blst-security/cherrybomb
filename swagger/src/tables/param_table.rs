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
    //probably will become an Enum
    //from:String,
    eps:Vec<String>,
    parents:Vec<String>,
    children:Vec<String>,
    max:Option<i64>,
    min:Option<i64>,
    default:Option<SchemaStrInt>,
}
impl ParamForTable{
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
    where T:OAS+Clone{
        ParamTable{
            info:oas.info(),          
            servers:oas.servers().unwrap_or(vec![]).iter().map(|s| s.url.clone()).collect(),
            params:Self::get_params(oas.clone()),
            eps:oas.get_paths().iter().map(|(p,i)| p).cloned().collect(),
        }
    }
    pub fn get_params<T>(oas:T)->Vec<ParamForTable>
    where T:OAS{
        let mut params:HashMap<ParamForTableKey,ParamForTableValue> = HashMap::new();
        vec![]
    }
}
