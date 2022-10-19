use super::*;
use colored::*;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackRequestBuilder {
    path: String,
    parameters: Vec<RequestParameter>,
    auth: Authorization,
    method: Method,
    headers: Vec<MHeader>,
    payload: String,
}
impl AttackRequestBuilder {
    pub fn uri2(&mut self, server: Server , path: &str , secure: bool) -> &mut Self {
        self.path = server.url + path;
        if let Some(vars) = server.variables {
            for (k, v) in vars {
                self.path = self.path.replace(&format!("{{{}}}", k), v.default.as_str());
            }
        }
        if !secure {
            self.path.replace_range(0..5, "http")
        }
        self
    }

    pub fn uri_http(&mut self, server: &Server) -> &mut Self { //build base url with http protocol
        let mut new_url = server.url.to_string(); 
        if let Some(var) = server.variables.clone() {
            for (key, value) in var {
                new_url = new_url.replace(&format!("{}{}{}", '{', key, '}'), &value.default);
                new_url.replace_range(0..5, "http");
            }
            // new_url.pop();
            self.path = new_url;
        } else {
            self.path = server.url.clone();
        }
        self
    }

    pub fn uri(&mut self, server: &Option<Vec<Server>>, path: &str) -> &mut Self {
        // servers
        if let Some(server_value) = server {
            let server_object = server_value.get(0).unwrap();
            let mut new_url = server_object.url.to_string();
            if let Some(var) = server_object.variables.clone() {
                for (key, value) in var {
                    new_url = new_url.replace(&format!("{}{}{}", '{', key, '}'), &value.default);
                }
                new_url.pop();
                self.path = format!("{}{}", new_url, path);
            } else {
                self.path = format!("{}{}", server_object.url, path);
            }

            return self;
        }
        self
    }

    pub fn auth(&mut self, auth: Authorization) -> &mut Self {
        self.auth = auth;
        self.add_auth_to_params();
        self
    }
    pub fn method(&mut self, method: Method) -> &mut Self {
        self.method = method;
        self
    }
    pub fn headers(&mut self, headers: Vec<MHeader>) -> &mut Self {
        self.headers = headers;
        self
    }
    pub fn parameters(&mut self, parameters: Vec<RequestParameter>) -> &mut Self {
        self.parameters = parameters;
        self
    }
    pub fn payload(&mut self, payload: &str) -> &mut Self {
        self.payload = payload.to_string();
        self
    }
    pub fn add_auth_to_params(&mut self) {
        if let Some(a) = self.auth.get_auth() {
            self.parameters.push(a);
        }
    }
    pub fn build(&self) -> AttackRequest {
        AttackRequest {
            path: self.path.clone(),
            parameters: self.parameters.clone(),
            auth: self.auth.clone(),
            method: self.method,
            headers: self.headers.clone(),
            payload: self.payload.clone(),
        }
    }
}
impl std::fmt::Display for AttackRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mut payload, query, path, headers) = self.params_to_payload();
        if payload.trim().is_empty() {
            payload = "NONE".to_string();
        }
        write!(
            f,
            "{}: {}{}\t{}: {}\t{}: {}\t{}: {}",
            "Path".green().bold(),
            path.magenta(),
            query.magenta(),
            "Method".green().bold(),
            self.method.to_string().magenta(),
            "Payload".green().bold(),
            payload.magenta(),
            "Headers".green().bold(),
            format!("{:?}", headers).magenta()
        )
    }
}
impl AttackRequest {
    pub fn builder() -> AttackRequestBuilder {
        AttackRequestBuilder::default()
    }
    pub fn params_to_payload(&self) -> (String, String, String, Vec<MHeader>) {
        let mut query = String::from('?');
        let mut path_ext = self.path.to_string();
        let mut headers = vec![];
        let mut payload = self.payload.clone();
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
        //  println!("{}", path_ext);
        (payload, query, path_ext, headers)
    }
    pub fn get_headers(&self, payload_headers: &[MHeader]) -> HashMap<String, String> {
        self.headers
            .iter()
            .chain(payload_headers)
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    }

    pub async fn send_request(&self, print: bool) -> Result<AttackResponse, reqwest::Error> {
        let client = reqwest::Client::new();
        let method1 = reqwest::Method::from_bytes(self.method.to_string().as_bytes()).unwrap();
        let (req_payload, req_query, path, headers1) = self.params_to_payload();
        let mut h = self.get_headers(&headers1);
        h.insert("X-BLST-ATTACKER".to_string(), "true".to_string());
        let req = client
            .request(method1, &format!("{}{}", path, req_query))
            .body(req_payload.clone())
            .headers((&h).try_into().expect("not valid headers"))
            .header("content-type", "application/json")
            .build()
            .unwrap();
        match client.execute(req).await {
            Ok(res) => {
                if print {
                    println!("{}: {}", "Request".bright_blue().bold(), self);
                }
                Ok(AttackResponse {
                    status: res.status().into(),
                    headers: res
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.to_string(), format!("{:?}", v)))
                        .collect(),
                    payload: res.text().await.unwrap_or_default(),
                })
            }
            Err(e) => {
                println!("{}: {}", "FAILED TO EXECUTE".red().bold().blink(), self);
                Err(e)
            }
        }
    }
}
