use super::*;

#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq,Hash)]
pub struct Header{
    pub name:String, 
    pub value:String,
}
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq,Hash)]
pub struct HeaderMap{
    pub headers:Vec<Header>,    
}
impl HeaderMap{
    pub fn new(headers:Vec<Header>)->HeaderMap{
        HeaderMap{headers}
    }
    pub fn insert(&mut self,header:Header){
        //shouldn't exist
        if !self.headers.contains(&header){
            self.headers.push(header);
        }
    }
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq,Hash)]
pub struct Split<T>{
    pub values:Vec<T>,
    percentages:Vec<u8>,
}
impl <T>Default for Split<T>
where T:PartialEq+Eq+Hash+Clone{
    fn default()->Self{
        Split{values:vec![],percentages:vec![]}
    }
}
impl <T>Split<T>
where T:PartialEq+Eq+Hash+Clone+Default{
    pub fn insert(&mut self,value:T,percentage:u8){
        //shouldn't exist
        if !self.values.contains(&value){
            self.values.push(value);
            self.percentages.push(percentage);
        }
    }
    pub fn from_hashmap(hashmap:&HashMap<T,u32>)->Self{
        let total:u32 = hashmap.values().sum();
        let values = hashmap.keys().map(|k| k.clone()).collect::<Vec<T>>();
        let percentages = hashmap.values().map(|v| ((v * 100)/total) as u8).collect::<Vec<u8>>();
        Split{values,percentages}
    }
    pub fn greatest(&self)->(T,u8){
        let mut p = 0;
        let mut v = T::default();
        for i in 0..self.values.len(){
            if self.percentages[i]>p{
                p = self.percentages[i];
                v = self.values[i].clone();
            }
        }
        (v,p)
    }
    pub fn filter(&mut self){
        let mut new_vals = vec![];
        let mut new_pers = vec![];
        for (v,p) in self.values.iter().zip(self.percentages.iter()){
            if *p>2{
                new_vals.push(v.clone());
                new_pers.push(*p);
            }
        }
        self.values = new_vals;
        self.percentages = new_pers;
    }
    pub fn get(&self,val:&T)->Option<u8>{
        if let Some(pos) = self.values.iter().position(|v|v==val){
            Some(self.percentages[pos])
        }else{
           None 
        }
    }
}
//pub type Split= HashMap<String,u8>; 
//pub type HeaderMap = HashMap<String,String>;
#[derive(Debug,Copy,Clone,Serialize,Deserialize,PartialEq,Eq,Hash)]
pub enum Method{
    GET,
    POST,
    OPTIONS,
    PATCH,
    DELETE,
    Other,
}
impl Default for Method{
    fn default()->Self{
        Method::GET
    }
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub enum Token{
    Uuid(Uuid),
    String(String),
    Number(u64),
    JWT(String),
}
impl Default for Token{
    fn default()->Self{
        Self::String(String::new())
    }
}
impl Token{
    pub fn read(s:String)->Token{
        if let Ok(u) = Uuid::parse_str(&s){
            Token::Uuid(u)
        }else if let Ok(i) = s.parse::<u64>(){
            Token::Number(i)
        }else{
            Token::String(s)
        }
    }
}
pub fn conv_json_pairs(s:&String)->Vec<ParamPayload>{
    let jj:HashMap<String,String> = match serde_json::from_str(s){
        Ok(json)=>json,
        Err(_)=>{ return vec![]; }, 
    };
    let mut ret = vec![];
    for key in jj.keys(){
        ret.push(ParamPayload{param:key.clone(),payload:jj[key].clone()});
    }
    ret
}
