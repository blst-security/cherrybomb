use hyper::{body, Body, Client, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use std::fs::File;
use std::io::{Read,Write};
use std::path::Path;


const TOKEN_FILE:&str = ".cherrybomb/token.txt";
async fn sign_up(filename:&Path,dir:&Path)->bool{
    let mut file = match File::create(filename) {
        Ok(f) => f,
        Err(_) => {
            match std::fs::create_dir(dir){
                Ok(_)=>{
                    match File::create(filename) {
                        Ok(f)=>f,
                        Err(_)=>{
                            return false;
                        }
                    }
                }
                Err(_)=>{
                    return false;
                }
            }
        }
    };
    let res = match reqwest::get("https://cherrybomb.blstsecurity.com/token").await{
        Ok(r)=>{
            match r.text().await{
                Ok(t)=>t,
                Err(_)=>{
                    return false;
                }
            }
        },
        Err(_)=>{
            return false;
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&res) {
        Ok(j) => j,
        Err(_) => {
            return false;
        }
    };
    match file.write_all(json["client_token"].to_string().as_bytes()){
        Ok(_)=>(),
        Err(_)=>{
            return false;
        }
    }
    true
}
async fn get_token()->String{
    let mut filename =  dirs::home_dir().unwrap();
    filename.push(TOKEN_FILE);
    let dir = dirs::home_dir().unwrap();
    let mut file = match File::open(&filename) {
        Ok(f) => f,
        Err(_) => {
            if sign_up(&filename,&dir).await{
                match File::open(&filename) {
                    Ok(f)=>f,
                    Err(_)=>{
                        return String::new();
                    }
                }
            }else{
                return String::new();
            }
        }
    };
    let mut token = String::new();
    match file.read_to_string(&mut token) {
        Ok(_) => (),
        Err(_) => {
            return String::new();
        }
    }
    token
}
pub async fn get_access(action: &str) -> bool {
    let token = get_token().await;
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    let client = Client::builder().build(connector);
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://cherrybomb.blstsecurity.com/auth")
        .body(Body::from(format!(
            "{{\"client_token\":{},\"action\":\"{}\"}}",
            token, action
        ).replace('\n',"")))
        .unwrap();
    let r = match client.request(req).await {
        Ok(r) => r,
        Err(_) => {
            return false;
        }
    };
    let txt = body::to_bytes(r.into_body()).await.unwrap();
    let json: serde_json::Value = match serde_json::from_slice(&txt) {
        Ok(j) => j,
        Err(_) => {
            return false;
        }
    };
    match json["opt_in"].as_bool() {
        Some(b) => {
            b
        }
        None => {
            false
        }
    }
}
