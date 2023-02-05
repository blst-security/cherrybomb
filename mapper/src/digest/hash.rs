use super::*;
use serde_with::serde_as;
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LinkHash {
    pub from: Endpoint,
    #[serde_as(as = "Vec<(_, _)>")]
    pub to: HashMap<Endpoint, u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LinksHash {
    links: Vec<LinkHash>,
}
impl LinksHash {
    pub fn get(&self, val: &Endpoint) -> Option<HashMap<Endpoint, u64>> {
        self.links.iter().position(|l| &l.from == val).map(|pos| self.links[pos].to.clone())
    }
    pub fn keys(&self) -> Vec<Endpoint> {
        self.links
            .iter()
            .map(|f| f.from.clone())
            .collect::<Vec<Endpoint>>()
    }
    pub fn load_data(&mut self, links: Vec<Link>) {
        let mut froms = self
            .links
            .iter()
            .map(|f| f.from.clone())
            .collect::<Vec<Endpoint>>();
        for link in links {
            if let Some(pos) = froms.iter().position(|lf| lf == &link.from) {
                let to1 = self.links[pos].to.entry(link.to).or_insert(0);
                *to1 += 1;
            } else {
                let mut to = HashMap::new();
                to.insert(link.to, 1);
                self.links.push(LinkHash {
                    from: link.from.clone(),
                    to,
                });
                froms.push(link.from);
            }
        }
    }
}
pub type LinksHashRef = HashMap<String, HashMap<String, u64>>;
/*
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]
pub struct LinkHashRef{
    pub from:String,
    pub to:HashMap<String,u64>,
}
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]
pub struct LinksHashRef{
    links:Vec<LinkHashRef>,
}*/
#[derive(Copy,Debug, Clone, Serialize, Deserialize, Eq, PartialEq,Hash)]
pub enum AuthHash{
    None,
    Basic,
    Bearer,
    Digest,
    Hawk,
    AWS,
    //Negotiate,
    Other,
}
impl Default for AuthHash {
    fn default() -> Self {
        Self::None
    }
}
impl AuthHash{
    pub fn from(s:String)->Self{
        let s = s.trim().to_lowercase();
        if s.starts_with("bearer"){
            AuthHash::Bearer
        }else if s.starts_with("basic"){
            AuthHash::Basic
        }else if s.starts_with("digest"){
            AuthHash::Digest
        }else if s.starts_with("hawk"){
            AuthHash::Hawk
        }else if s.starts_with("aws"){
            AuthHash::AWS
        }else{
            AuthHash::Other
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeaderHash{
    //General
    #[serde(rename = "user-agent")]
    UserAgent(HashMap<String,u32>),
    #[serde(rename = "content_length")]
    ContentLength(HashMap<u32,u32>),
    #[serde(rename = "content_type")]
    ContentType(HashMap<String,u32>),
    #[serde(rename = "host")]
    Host(HashMap<String,u32>),
    #[serde(rename = "csp")]
    CSP(HashMap<String,u32>),
    //Auth
    #[serde(rename = "authorization")]
    AuthHash(HashSet<AuthHash>),
    #[serde(rename = "jwt")]
    JWT,
    //Other - keeps only the header name
    Other(HashSet<String>),
}
fn entry_inc<T>(map:&mut HashMap<T,u32>,val:T)
where T:Eq+Hash{
    let c = map.entry(val).or_insert(0);
    *c+=1;
}
impl HeaderHash{
    pub fn name(&self)->String{
        match self{
            Self::UserAgent(_)=>String::from("user-agent"),
            Self::ContentLength(_)=>String::from("content-length"),
            Self::ContentType(_)=>String::from("content-type"),
            Self::Host(_)=>String::from("host"),
            Self::CSP(_)=>String::from("csp"),
            Self::JWT=>String::from("jwt"),
            Self::AuthHash(_)=>String::from("authorization"),
            _=>String::from("other"),
        }
    }
    pub fn is_other(name:&str)->bool{
        let v1 = vec!["user-agent","content-length","content-type","host","csp","jwt","authorization"];
        !v1.contains(&name.to_lowercase().trim()) 
    }
    pub fn insert(&mut self,val:String){
        match self{
            Self::UserAgent(v)=>entry_inc(v,val),
            Self::ContentLength(v)=>entry_inc(v,val.parse::<u32>().unwrap()),
            Self::ContentType(v)=>entry_inc(v,val),
            Self::Host(v)=>entry_inc(v,val),
            Self::CSP(v)=>entry_inc(v,val),
            Self::JWT=>(),
            Self::AuthHash(v)=>{v.insert(AuthHash::from(val));},
            Self::Other(v)=>{v.insert(val);},
        };
    }
    pub fn from(header:Header)->Self{
        match header.name.to_lowercase().trim(){
            "user-agent"=>Self::UserAgent(HashMap::from([(header.value,1)])),
            "content-length"=>Self::ContentLength(HashMap::from([(header.value.parse::<u32>().unwrap(),1)])),
            "content-type"=>Self::ContentType(HashMap::from([(header.value,1)])),
            "host"=>Self::Host(HashMap::from([(header.value,1)])),
            "csp"=>Self::CSP(HashMap::from([(header.value,1)])),
            "jwt"=>Self::JWT,
            "authorization"=>Self::AuthHash(HashSet::from([AuthHash::from(header.value)])),
            _=>Self::Other(HashSet::from([header.name])),
        }
    }
    pub fn get_val(&self)->EpHeaderValue{
        match self{
            Self::UserAgent(v)=>EpHeaderValue::Const(StrNum::String(Split::from_hashmap(v).greatest().0)),
            Self::ContentLength(v)=>EpHeaderValue::Const(StrNum::Number(Split::from_hashmap(v).greatest().0)),
            Self::ContentType(v)=>EpHeaderValue::Const(StrNum::String(Split::from_hashmap(v).greatest().0)),
            Self::Host(v)=>EpHeaderValue::Const(StrNum::String(Split::from_hashmap(v).greatest().0)),
            Self::CSP(v)=>EpHeaderValue::Const(StrNum::String(Split::from_hashmap(v).greatest().0)),
            Self::JWT=>EpHeaderValue::AuthToken,
            Self::AuthHash(_)=>EpHeaderValue::AuthToken,
            Self::Other(_)=>EpHeaderValue::default(),
        }
    }
}
pub type HeadersHash = Vec<HeaderHash>;
pub fn add_to_headers_hash(headers_hash:&mut HeadersHash,header:Header){
    if let Some(pos) = headers_hash.iter().position(|h| h.name() == header.name){
        headers_hash[pos].insert(header.value);
    }else if HeaderHash::is_other(&header.name){
        if let Some(pos) = headers_hash.iter().position(|h| h.name() == *"other"){
            headers_hash[pos].insert(header.name);
        }else{
            headers_hash.push(HeaderHash::Other(HashSet::from([header.name])));
        }
    }else {
        headers_hash.push(HeaderHash::from(header));
    }
}
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EndpointHash {
    pub path: String,//Path,
    #[serde_as(as = "Vec<(_, _)>")]
    pub dm: HashMap<QuePay, u32>,
    #[serde_as(as = "Vec<(_, _)>")]
    pub methods: HashMap<Method, u32>,
    pub req_headers: HeadersHash,//HashMap<String, HashMap<String, u32>>,
    pub res_headers: HeadersHash,//HashMap<String, HashMap<String, u32>>,
    pub status_payloads: ParamPayloadH,
    pub queries: ParamPayloadH, 
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct ParamPayload {
    pub param: String,
    pub payload: String,
}
type ParamPayloadHash = Vec<ParamPayload>;
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamPayloadH {
    pub reqp_map: HashMap<String, HashSet<String>>,
    pub resp_map: HashMap<String, HashMap<String, u32>>,
    pub status_map: HashMap<u16, u32>,
}
impl EndpointHash {
    pub fn new(path: String) -> EndpointHash {
        EndpointHash {
            path,
            ..EndpointHash::default()
        }
    }
    //response payload should be change to ParamPayload type ish
    pub fn add_pp(
        &mut self,
        req_param_payload: &ParamPayloadHash,
        status: u16,
        res_param_payload: &ParamPayloadHash,
        t: bool,
    ) {
        // if it does not change than change it back or change it to tmp
        let mut taker = if t {
            let m = self.dm.entry(QuePay::Query).or_insert(0);
            *m += 1;
            self.queries.clone()
        } else {
            let m = self.dm.entry(QuePay::Payload).or_insert(0);
            *m += 1;
            self.status_payloads.clone()
        };
        for pp in req_param_payload {
            if let Some(req_payload) = taker.reqp_map.get_mut(&pp.param) {
                req_payload.insert(pp.payload.clone());
            } else {
                let mut hs = HashSet::new();
                hs.insert(pp.payload.clone());
                taker.reqp_map.insert(pp.param.clone(), hs);
            }
        }
        for pp in res_param_payload {
            if let Some(res_payload) = taker.resp_map.get_mut(&pp.param) {
                let rp = res_payload.entry(pp.payload.clone()).or_insert(0);
                *rp += 1;
            } else {
                let mut hm = HashMap::new();
                hm.insert(pp.payload.clone(), 1);
                taker.resp_map.insert(pp.param.clone(), hm);
            }
        }
        let st = taker.status_map.entry(status).or_insert(0);
        *st += 1;
        /*
        if let Some(payload) = taker.resp_map.get_mut(&status){
            let p1 = payload.entry(response_payload).or_insert(0);
            *p1+=1;
        }else{
            let mut hm = HashMap::new();
            hm.insert(response_payload,1);
            taker.resp_map.insert(status,hm);
        }*/
        if t {
            self.queries = taker
        } else {
            self.status_payloads = taker
        }
    }
    pub fn add_headers(&mut self, headers: &HashMap<String, String>, t: bool) {
        // if it does not change than change it back or change it to tmp
        let mut taker = if t {
            self.req_headers.clone()
        } else {
            self.res_headers.clone()
        };
        for (name,value) in headers{
            add_to_headers_hash(&mut taker,Header::from(name,value));
        }
        if t {
            self.req_headers = taker
        } else {
            self.res_headers = taker
        }
    }
    pub fn load(&mut self, req_res: &ReqRes) {
        let mtd = self.methods.entry(req_res.method).or_insert(0);
        *mtd += 1;
        self.add_headers(&req_res.req_headers, true);
        self.add_headers(&req_res.res_headers, false);
        let query_pairs: ParamPayloadHash = conv_json_pairs(&req_res.req_query); //Url::parse(&req_res.path).unwrap().query_pairs().into_owned().map(|p| ParamPayload{param:p.0,payload:p.1}).collect();
        let res_pairs: ParamPayloadHash = conv_json_pairs(&req_res.res_payload);
        self.add_pp(&query_pairs, req_res.status, &res_pairs, true);
        let req_pairs: ParamPayloadHash = conv_json_pairs(&req_res.req_payload);
        self.add_pp(&req_pairs, req_res.status, &res_pairs, false);
    }
}
/*
pub fn add_req_headers(&mut self,headers:HashMap<String,String>){
    for h in headers.keys(){
        let v2 = headers.get(h).unwrap().to_string();
        if let Some(v) = self.req_headers.get_mut(h){
            // if v2 is an entry in v then it will take it's value, if not it will insert it
            // with the value of one.
            let v3 = v.entry(v2).or_insert(0);
            *v3+=1;
        }else{
            let mut h1 = HashMap::new();
            h1.insert(v2,1);
            self.req_headers.insert(h.to_string(),h1);
        }
    }
}
pub fn add_res_headers(&mut self,headers:HashMap<String,String>){
    for h in headers.keys(){
        let v2 = headers.get(h).unwrap().to_string();
        if let Some(v) = self.res_headers.get_mut(h){
            // if v2 is an entry in v then it will take it's value, if not it will insert it
            // with the value of one.
            let v3 = v.entry(v2).or_insert(0);
            *v3+=1;
        }else{
            let mut h1 = HashMap::new();
            h1.insert(v2,1);
            self.res_headers.insert(h.to_string(),h1);
        }
    }
}*/
/*#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq,Hash)]
struct ParamPayloadHash{
    params:Vec<String>,
    payloads:Vec<String>,
}*/
//type QP = HashMap<QueryHash,HashMap<u16,HashMap<String,u32>>>;
/*
fn add_to_rr<K,V,T>(hashmap:&mut HashMap<K,V>,val1:K,val2:V)
    where K:Clone+Hash+Eq, V:Clone+Eq{
    if let Some(val) = hashmap.get_mut(&val1){

    }
}*/
//pub type LinkHash = HashMap<Endpoint,HashMap<Endpoint,u64>>;
//type SP =HashMap<u16,HashMap<String,u32>>;
//type ParamPayload = HashMap<ParamPayloadHash,SP>;
