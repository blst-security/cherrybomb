use super::*;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NumDescriptor {
    //FRange((f64,f64)),
    Range((i64, i64)),
    //FList(Vec<f64>),
    List(Vec<i64>),
    Random,
}
impl NumDescriptor {
    pub fn matches(&self, num: i64) -> bool {
        match self {
            Self::Range((s, e)) => &num >= s && &num <= e,
            Self::List(l) => l.contains(&num),
            Self::Random => true,
        }
    }
}
impl Default for NumDescriptor {
    fn default() -> Self {
        Self::Random
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StringDescriptor {
    Similar,
    Uuid(u8),
    List(Vec<String>),
    Random,
}
impl StringDescriptor {
    pub fn matches(&self, string: &str) -> bool {
        match self {
            Self::Uuid(v) => {
                if let Ok(u) = Uuid::parse_str(string) {
                    u.get_version_num() as u8 == *v
                } else {
                    false
                }
            }
            Self::List(l) => l.contains(&(string.to_string())),
            Self::Random => true,
            _ => true,
        }
    }
}
impl Default for StringDescriptor {
    fn default() -> Self {
        Self::Random
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NumType {
    Integer,
    Float,
    //UInt,
}
impl Default for NumType {
    fn default() -> Self {
        Self::Integer
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ValueDescriptor {
    Number((NumDescriptor, NumType)),
    String(StringDescriptor),
    Bool,
    Unknown,
}
impl Default for ValueDescriptor {
    fn default() -> Self {
        Self::Unknown
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct ParamDescriptor {
    pub from: QuePay,
    pub name: String,
    pub value: ValueDescriptor,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct PayloadDescriptor {
    pub params: Vec<ParamDescriptor>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct RRPayload {
    pub status: Split<u16>,
    pub req_payload: PayloadDescriptor,
    pub res_payload: PayloadDescriptor,
}
/*
impl RRPayload{
    pub fn from_hash(hash:EndpointHash)->Self{
        for pph in hash.keys(){
            for pp in pph
        }
    }
}*/
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub common_req_headers: HeaderMap,
    pub common_res_headers: HeaderMap,
    pub path: Path,
    pub methods: Split<Method>,
    pub payload_delivery_methods: Split<QuePay>,
    pub req_res_payloads: RRPayload,
}
