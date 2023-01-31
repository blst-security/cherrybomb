use crate::scan::active::http_client::auth::Authorization;
use crate::scan::active::http_client::{
    AttackRequest, AttackResponse, MHeader, QuePay, RequestParameter,
};
use cherrybomb_oas::legacy::legacy_oas::*;
use cherrybomb_oas::legacy::utils::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackRequestBuilder {
    servers: Vec<Server>,
    path: String,
    parameters: Vec<RequestParameter>,
    auth: Authorization,
    method: Method,
    headers: Vec<MHeader>,
    payload: String,
}

impl AttackRequestBuilder {
    pub fn uri2(&mut self, server: Server, path: &str, secure: bool) -> &mut Self {
        self.path = server.base_url + path;
        if let Some(vars) = server.variables {
            for (k, v) in vars {
                self.path = self.path.replace(&format!("{{{k}}}"), v.default.as_str());
            }
        }
        if !secure {
            self.path.replace_range(0..5, "http")
        }
        self
    }
    pub fn servers(&mut self, servers: Option<Vec<Server>>, secure: bool) -> &mut Self {
        if let Some(servers) = servers {
            for server in servers {
                let mut new_server_addr = server.base_url.clone();
                if let Some(vars) = &server.variables {
                    for (k, v) in vars {
                        new_server_addr =
                            new_server_addr.replace(&format!("{{{k}}}"), v.default.as_str());
                    }
                }
                if !secure & new_server_addr.starts_with("https") {
                    new_server_addr.replace_range(0..5, "http")
                }
                self.servers.push(Server {
                    base_url: new_server_addr,
                    description: server.description,
                    variables: server.variables,
                });
            }
        }
        //TODO implement error here
        else {
            println!("No servers supplied")
        }
        self
    }

    pub fn path(&mut self, path: &str) -> &mut Self {
        self.path = path.to_string();
        self
    }

    pub fn uri_http(&mut self, server: &Server) -> &mut Self {
        //build base url with http protocol
        let mut new_url = server.base_url.to_string();
        if let Some(var) = server.variables.clone() {
            for (key, value) in var {
                new_url = new_url.replace(&format!("{}{}{}", '{', key, '}'), &value.default);
                new_url.replace_range(0..5, "http");
            }
            // new_url.pop();
            self.path = new_url;
        } else {
            self.path = server.base_url.clone();
        }
        self
    }

    pub fn uri(&mut self, server: &Option<Vec<Server>>, path: &str) -> &mut Self {
        // servers
        if let Some(server_value) = server {
            let server_object = server_value.get(0).unwrap();
            let mut new_url = server_object.base_url.to_string();
            if let Some(var) = server_object.variables.clone() {
                for (key, value) in var {
                    new_url = new_url.replace(&format!("{}{}{}", '{', key, '}'), &value.default);
                }
                new_url.pop();
                self.path = format!("{new_url}{path}");
            } else {
                self.path = format!("{}{}", server_object.base_url, path);
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
        self.parameters.extend(parameters);
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
            servers: self.servers.clone(),
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
            "Path: {path}{query}\t\
            Method: {}\t\
            Payload: {payload}\t\
            Headers: {headers:?}",
            self.method,
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
        (payload, query, path_ext, headers)
    }

    pub fn get_headers(&self, payload_headers: &[MHeader]) -> HashMap<String, String> {
        self.headers
            .iter()
            .chain(payload_headers)
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    }
    pub async fn send_request_with_response(&self) -> (String, bool) {
        let client = reqwest::Client::new();
        let method1 = reqwest::Method::from_bytes(self.method.to_string().as_bytes()).unwrap();
        let (req_payload, req_query, path, headers1) = self.params_to_payload();
        let h = self.get_headers(&headers1);

        //   h.insert("X-BLST-ATTACKER".to_string(), "true".to_string());
        let req = client
            .request(method1, format!("{path}{req_query}"))
            .body(req_payload.clone())
            .headers((&h).try_into().expect("not valid headers"))
            // .header("content-type", "application/json")
            .send();

        match req.await {
            Ok(res) => {
                if res.status() == 200 {
                    match res.text().await {
                        Ok(final_resp) => (final_resp, true),
                        Err(e) => (e.to_string(), false),
                    }
                } else {
                    ("error".to_string(), false)
                }
            }
            Err(e) => {
                println!("FAILED TO EXECUTE: {self}");
                (e.to_string(), false)
            }
        }
    }

    pub async fn send_request(&self, print: bool) -> Result<AttackResponse, reqwest::Error> {
        let client = reqwest::Client::new();
        let method1 = reqwest::Method::from_bytes(self.method.to_string().as_bytes()).unwrap();
        let (req_payload, req_query, path, headers1) = self.params_to_payload();
        let h = self.get_headers(&headers1);
        //   h.insert("X-BLST-ATTACKER".to_string(), "true".to_string());
        let req = client
            .request(method1, format!("{path}{req_query}"))
            .body(req_payload.clone())
            .headers((&h).try_into().expect("not valid headers"))
            //.header("content-type", "application/json")
            .build()
            .unwrap();
        // dbg!(&req);
        match client.execute(req).await {
            Ok(res) => {
                if print {
                    println!("Request: {self}");
                }
                Ok(AttackResponse {
                    status: res.status().into(),
                    headers: res
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.to_string(), format!("{v:?}")))
                        .collect(),
                    payload: res.text().await.unwrap_or_default(),
                })
            }
            Err(e) => {
                println!("FAILED TO EXECUTE: {self}");
                Err(e)
            }
        }
    }
    pub async fn send_request_all_servers(&self, print: bool) -> Vec<AttackResponse> {
        let client = reqwest::Client::new();
        let method1 = reqwest::Method::from_bytes(self.method.to_string().as_bytes()).unwrap();
        let (req_payload, req_query, path, headers1) = self.params_to_payload();
        let mut h = self.get_headers(&headers1);
        //    dbg!(&headers1);
        h.insert("X-BLST-ATTACKER".to_string(), "true".to_string());
        let mut ret = vec![];
        for server in &self.servers {
            let req = client
                .request(
                    method1.clone(),
                    format!("{}{}{}", server.base_url, path, req_query),
                )
                .body(req_payload.clone())
                .headers((&h).try_into().expect("not valid headers"))
                .build()
                .unwrap(); //TODO return builder error
            match client.execute(req).await {
                Ok(res) => {
                    if print {
                        println!("Request: {self}");
                    }
                    ret.push(AttackResponse {
                        status: res.status().into(),
                        headers: res
                            .headers()
                            .iter()
                            .map(|(n, v)| (n.to_string(), format!("{v:?}")))
                            .collect(),
                        payload: res.text().await.unwrap_or_default(),
                    })
                }
                Err(e) => {
                    println!("FAILED TO EXECUTE: {self} - ERROR: {e}");
                }
            }
        }
        ret
    }
}
