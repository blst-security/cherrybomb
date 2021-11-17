use super::*;
use serde_with::serde_as;
#[serde_as]
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]
pub struct LinkHash{
    pub from:Endpoint,
    #[serde_as(as = "Vec<(_, _)>")]
    pub to:HashMap<Endpoint,u64>,
}
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]
pub struct LinksHash{
    links:Vec<LinkHash>,
}
impl LinksHash{
    pub fn get(&self,val:&Endpoint)->Option<HashMap<Endpoint,u64>>{
        if let Some(pos) = self.links.iter().position(|l| &l.from == val){
            Some(self.links[pos].to.clone())
        }else{
            None
        }
    }
    pub fn keys(&self)->Vec<Endpoint>{
        self.links.iter().map(|f| f.from.clone()).collect::<Vec<Endpoint>>()
    }
    pub fn load_data(&mut self,links:Vec<Link>){
        let mut froms = self.links.iter().map(|f| f.from.clone()).collect::<Vec<Endpoint>>();
        for link in links{
            if let Some(pos) = froms.iter().position(|lf| lf == &link.from){
                let to1 = self.links[pos].to.entry(link.to).or_insert(0);
                *to1+=1;
            }else{
                let mut to = HashMap::new();
                to.insert(link.to,1);
                self.links.push(LinkHash{from:link.from.clone(),to});
                froms.push(link.from);
            }
        }
    }
}
pub type LinksHashRef = HashMap<String,HashMap<String,u64>>;
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
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq,Hash)]
pub enum QuePay{
    Query,
    Payload,
    Response,
}
impl Default for QuePay{
    fn default()->Self{
        Self::Payload
    }
}
#[serde_as]
#[derive(Debug,Clone,Serialize,Deserialize,Default)]
pub struct EndpointHash{
    pub path:String,
    #[serde_as(as = "Vec<(_, _)>")]
    pub dm:HashMap<QuePay,u32>,
    #[serde_as(as = "Vec<(_, _)>")]
    pub methods:HashMap<Method,u32>,
    pub req_headers:HashMap<String,HashMap<String,u32>>,
    pub res_headers:HashMap<String,HashMap<String,u32>>,
    pub status_payloads:ParamPayloadH,
    pub queries:ParamPayloadH//HashMap<String,HashMap<String,u32>>,
}
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq,Hash)]
pub struct ParamPayload{
    pub param:String,
    pub payload:String,
}
type ParamPayloadHash = Vec<ParamPayload>;
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]
pub struct ParamPayloadH{
    pub reqp_map:HashMap<String,HashSet<String>>,
    pub resp_map:HashMap<String,HashMap<String,u32>>,
    pub status_map:HashMap<u16,u32>,
}
impl EndpointHash{
    pub fn new(path:String)->EndpointHash{
        EndpointHash{
            path,
            ..EndpointHash::default()
        }
    }
    //response payload should be change to ParamPayload type ish
    pub fn add_pp(&mut self, req_param_payload:&ParamPayloadHash,status:u16,res_param_payload:&ParamPayloadHash,t:bool){
        // if it does not change than change it back or change it to tmp
        let mut taker = if t{ 
            let m = self.dm.entry(QuePay::Query).or_insert(0);
            *m+=1;
            self.queries.clone() 
        } else { 
            let m = self.dm.entry(QuePay::Payload).or_insert(0);
            *m+=1;
            self.status_payloads.clone() 
        };
        for pp in req_param_payload{
            if let Some(req_payload) = taker.reqp_map.get_mut(&pp.param){
                req_payload.insert(pp.payload.clone());
            }else{
                let mut hs = HashSet::new();
                hs.insert(pp.payload.clone()); 
                taker.reqp_map.insert(pp.param.clone(),hs);
            }
        }
        for pp in res_param_payload{
            if let Some(res_payload) = taker.resp_map.get_mut(&pp.param){
                let rp = res_payload.entry(pp.payload.clone()).or_insert(0);
                *rp+=1;
            }else{
                let mut hm = HashMap::new();
                hm.insert(pp.payload.clone(),1); 
                taker.resp_map.insert(pp.param.clone(),hm);
            }
        }
        let st = taker.status_map.entry(status).or_insert(0);
        *st+=1;
        /*
        if let Some(payload) = taker.resp_map.get_mut(&status){
            let p1 = payload.entry(response_payload).or_insert(0);
            *p1+=1;
        }else{
            let mut hm = HashMap::new();
            hm.insert(response_payload,1);
            taker.resp_map.insert(status,hm);
        }*/
        if t{ self.queries = taker } else { self.status_payloads = taker }
    }
    pub fn add_headers(&mut self,headers:&HashMap<String,String>,t:bool){
        // if it does not change than change it back or change it to tmp
        let mut taker = if t { self.req_headers.clone() } else { self.res_headers.clone() };
        for h in headers.keys(){
            let v2 = headers.get(h).unwrap().to_string();
            if let Some(v) = taker.get_mut(h){
                // if v2 is an entry in v then it will take it's value, if not it will insert it
                // with the value of one.
                let v3 = v.entry(v2).or_insert(0);
                *v3+=1;
            }else{
                let mut h1 = HashMap::new();
                h1.insert(v2,1);
                taker.insert(h.to_string(),h1);
            }
        }
        if t { self.req_headers = taker } else { self.res_headers = taker }
    }
    pub fn load(&mut self,req_res:&ReqRes){
        let mtd = self.methods.entry(req_res.method).or_insert(0);
        *mtd+=1;
        self.add_headers(&req_res.req_headers,true);
        self.add_headers(&req_res.res_headers,false);
        let query_pairs:ParamPayloadHash =conv_json_pairs(&req_res.req_query); //Url::parse(&req_res.path).unwrap().query_pairs().into_owned().map(|p| ParamPayload{param:p.0,payload:p.1}).collect();
        println!("Q:{:?}",&req_res.req_query);
        let res_pairs:ParamPayloadHash = conv_json_pairs(&req_res.res_payload);
        println!("RES:{:?}",&req_res.res_payload);
        self.add_pp(&query_pairs,req_res.status,&res_pairs,true);
        let req_pairs:ParamPayloadHash = conv_json_pairs(&req_res.req_payload);
        println!("REQ:{:?}",&req_res.req_payload);
        self.add_pp(&req_pairs,req_res.status,&res_pairs,true);
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
