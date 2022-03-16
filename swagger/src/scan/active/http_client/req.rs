use super::*;
use std::fmt;
use colored::*;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackRequestBuilder {
    path:String,
    parameters: Vec<RequestParameter>,
    auth: Authorization,
    method: Method,
    headers: Vec<MHeader>,
}
impl AttackRequestBuilder {
    pub fn uri(&mut self,base_url:&str,path:&str)->&mut Self{
        self.path =format!("{}{}", base_url, path);
        self
    }
    pub fn auth(&mut self,auth:Authorization)->&mut Self{
        self.auth = auth;
        self
    }
    pub fn method(&mut self,method:Method)->&mut Self{
        self.method = method;
        self
    }
    pub fn headers(&mut self,headers:Vec<MHeader>)->&mut Self{
        self.headers = headers;
        self
    }
    pub fn parameters(&mut self,parameters:Vec<RequestParameter>)->&mut Self{
        self.parameters = parameters;
        self
    }
    pub fn build(&self)->AttackRequest{
        AttackRequest {
            path:self.path.clone(),
            parameters:self.parameters.clone(),
            auth:self.auth.clone(),
            method:self.method.clone(),
            headers:self.headers.clone(),
        }
    }
}
impl std::fmt::Display for AttackRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mut payload,query,path,headers) = self.params_to_payload();  
        if payload.trim().len() ==0{
            payload = "NONE".to_string();
        }
        write!(f, "{}: {}{}\t{}: {}\t{}: {}\t{}: {}","Path".green().bold(),path.magenta(),query.magenta(),"Method".green().bold(),self.method.to_string().magenta(),"Payload".green().bold(),payload.magenta(),"Headers".green().bold(),format!("{:?}",headers).magenta())
    }
}
impl AttackRequest {
    pub fn builder()->AttackRequestBuilder{
        AttackRequestBuilder::default()
    }
    pub fn params_to_payload(&self) -> (String, String, String, Vec<MHeader>) {
        let mut payload = String::from('{');
        let mut query = String::from('?');
        let mut path_ext = self.path.to_string();
        let mut headers = vec![];
        for param in self.parameters.iter() {
            match param.dm {
                QuePay::Payload => {
                    payload.push_str(&format!("\"{}\":{},", param.name, param.value))
                }
                QuePay::Query => query.push_str(&format!("{}={}&", param.name, param.value)),
                QuePay::Path => {
                    path_ext =
                        path_ext.replace(&format!("{}{}{}", '{', param.name, '}'), &param.value)
                }
                QuePay::Headers => {
                    headers.push(MHeader {
                        name: param.name.clone(),
                        value: param.value.clone(),
                    });
                }
                _ => (),
            }
        }
        query.pop();
        if payload.trim() == "{" {
            payload = String::new();
        } else {
            payload.pop();
            payload.push('}');
        }
        (payload, query, path_ext, headers)
    }
    pub fn get_headers(&self,payload_headers: &[MHeader]) -> HashMap<String, String> {
        let mut new: Vec<MHeader> = self.headers
        .iter()
        .chain(payload_headers)
        .cloned()
        .collect();
        if let Some(a) = self.auth.get_header() {
            new.push(a);
        }
        new.iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    }

    pub async fn send_request(&self,print:bool) -> Result<AttackResponse,reqwest::Error> {
        let client = reqwest::Client::new();
        let method1 = reqwest::Method::from_bytes(self.method.to_string().as_bytes()).unwrap();
        let (req_payload, req_query, path, headers1) = self.params_to_payload();
        let h = self.get_headers(&headers1);
        let req = client
            .request(method1, &format!("{}{}", path, req_query))
            .body(req_payload.clone())
            .headers((&h).try_into().expect("not valid headers"))
            .build()
            .unwrap();
        match client.execute(req).await { 
            Ok(res)=> {
                if print{
                    println!("{}: {}","Request".bright_blue().bold(),self);
                }
                Ok(AttackResponse {
                    status: res.status().into(),
                    headers: res
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.to_string(), format!("{:?}", v)))
                        .collect(),
                    payload: res.text().await.unwrap_or(String::new()),
                })
            },
            Err(e)=>{
                println!("{}: {}","FAILED TO EXECUTE".red().bold().blink(),self); 
                Err(e)
            }
        }
    }
}
