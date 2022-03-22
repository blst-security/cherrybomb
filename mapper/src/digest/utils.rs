use super::*;
use std::fmt;


#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QuePay {
    Headers,
    Path,
    Query,
    Payload,
    Response,
    None
}
impl Default for QuePay {
    fn default() -> Self {
        Self::Payload
    }
}
impl fmt::Display for QuePay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use colored::*;
        match self{
            Self::Headers=>write!(f,"{:16}","Headers".bold().truecolor(253,186,116)),
            Self::Path=>write!(f,"{:16}","Path".bold().truecolor(147,197,253)),
            Self::Query=>write!(f,"{:16}","Query".bold().truecolor(134,239,172)),
            Self::Payload=>write!(f,"{:16}","Request Payload".bold().truecolor(253, 224, 71)),
            Self::Response=>write!(f,"{:16}","Response Payload".bold().truecolor(165, 180, 252)),
            Self::None=>write!(f,""),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct Header {
    pub name: String,
    pub value: String,
}
impl Header{
    pub fn from(name:&str,value:&str)->Header{
        Header{name:name.to_string(),value:value.to_string()}
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StrNum{
    String(String),
    Number(u32),
}
impl Default for StrNum {
    fn default() -> Self {
        Self::String(String::new())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EpHeaderValue{
    Payload(ParamDescriptor),
    Const(StrNum),
    AuthToken,
}
impl Default for EpHeaderValue {
    fn default() -> Self {
        Self::Const(StrNum::default())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct EpHeader{
    pub name:String,
    pub value:EpHeaderValue,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct HeaderMap {
    pub headers: Vec<EpHeader>,
}
impl HeaderMap {
    pub fn new(headers: Vec<EpHeader>) -> HeaderMap {
        HeaderMap { headers }
    }
    pub fn insert(&mut self, header: EpHeader) {
        //shouldn't exist
        if !self.headers.contains(&header) {
            self.headers.push(header);
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Split<T> {
    pub values: Vec<T>,
    percentages: Vec<u8>,
}
impl<T> Default for Split<T>
where
    T: PartialEq + Eq + Hash + Clone,
{
    fn default() -> Self {
        Split {
            values: vec![],
            percentages: vec![],
        }
    }
}
impl<T> Split<T>
where
    T: PartialEq + Eq + Hash + Clone + Default,
{
    pub fn insert(&mut self, value: T, percentage: u8) {
        //shouldn't exist
        if !self.values.contains(&value) {
            self.values.push(value);
            self.percentages.push(percentage);
        }
    }
    pub fn from_hashmap(hashmap: &HashMap<T, u32>) -> Self {
        let total: u32 = hashmap.values().sum();
        let values = hashmap.keys().cloned().collect::<Vec<T>>();
        let percentages = hashmap
            .values()
            .map(|v| ((v * 100) / total) as u8)
            .collect::<Vec<u8>>();
        Split {
            values,
            percentages,
        }
    }
    pub fn greatest(&self) -> (T, u8) {
        let mut p = 0;
        let mut v = T::default();
        for i in 0..self.values.len() {
            if self.percentages[i] > p {
                p = self.percentages[i];
                v = self.values[i].clone();
            }
        }
        (v, p)
    }
    pub fn filter(&mut self) {
        let mut new_vals = vec![];
        let mut new_pers = vec![];
        for (v, p) in self.values.iter().zip(self.percentages.iter()) {
            if *p > 2 {
                new_vals.push(v.clone());
                new_pers.push(*p);
            }
        }
        self.values = new_vals;
        self.percentages = new_pers;
    }
    pub fn get(&self, val: &T) -> Option<u8> {
        self.values.iter().position(|v| v == val).map(|pos| self.percentages[pos])
    }
}
//pub type Split= HashMap<String,u8>;
//pub type HeaderMap = HashMap<String,String>;
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Method {
    GET,
    POST,
    OPTIONS,
    PATCH,
    PUT,
    DELETE,
    HEAD,
    TRACE,
    Other,
}
impl Default for Method {
    fn default() -> Self {
            Method::GET
    }
}
impl Method {
    pub fn method_from_str(s: &str) -> Self {
        match s{
            "GET"=>Method::GET,
            "POST"=>Method::POST,
            "PUT"=>Method::PUT,
            "PATCH"=>Method::PATCH,
            "DELETE"=>Method::DELETE,
            "OPTIONS"=>Method::OPTIONS,
            "HEAD"=>Method::HEAD,
            "TRACE"=>Method::TRACE,
            _=>Method::Other,
        }
    }
}
impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self{
            Self::GET=>write!(f, "GET"),
            Self::POST=>write!(f, "POST"),
            Self::PUT=>write!(f, "PUT"),
            Self::OPTIONS=>write!(f, "OPTIONS"),
            Self::PATCH=>write!(f, "PATCH"),
            Self::DELETE=>write!(f, "DELETE"),
            Self::HEAD=>write!(f, "HEAD"),
            Self::TRACE=>write!(f, "TRACE"),
            Self::Other=>write!(f, "other"),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Token {
    Uuid(Uuid),
    String(String),
    Number(u64),
    JWT(String),
}
impl Default for Token {
    fn default() -> Self {
        Self::String(String::new())
    }
}
impl Token {
    pub fn read(s: String) -> Token {
        if let Ok(u) = Uuid::parse_str(&s) {
            Token::Uuid(u)
        } else if let Ok(i) = s.parse::<u64>() {
            Token::Number(i)
        } else {
            Token::String(s)
        }
    }
}
pub fn conv_json_pairs(s: &str) -> Vec<ParamPayload> {
    //if let Ok(json) = serde_json::from_str::<HashMap<String, String>>(s) {
    if let Ok(serde_json::Value::Object(json)) = serde_json::from_str::<serde_json::Value>(s) {
        let mut ret = vec![];
        for (param,payload) in json{
            ret.push(ParamPayload {
                param,
                payload:payload.to_string(),
            });
        }
        ret
    }else if s.trim().starts_with('?'){
        s[1..].split('&').map(|p|{
            let mut split = p.split('=');
            ParamPayload{
                param:split.next().unwrap().to_string(),
                payload:split.next().unwrap().to_string(),
            }
        }).collect::<Vec<ParamPayload>>()
    }else{
        vec![]
    }
}
