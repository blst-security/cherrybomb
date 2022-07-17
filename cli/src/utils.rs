use super::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
//use mapper::digest::*;
use colored::*;
//use std::collections::HashMap;
//use httparse::Status;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ClientReqRes {
    pub request: String,
    pub response: String,
}
/*
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq,Eq)]
pub struct Log {
    pub session: Vec<ClientReqRes>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebMapLink {
    pub from: String,
    pub to: String,
    pub strength: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebMapGroup {
    pub endpoints: Vec<String>,
    pub links: Vec<WebMapLink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebMap {
    pub eps: Vec<Endpoint>,
    pub groups: Vec<WebMapGroup>,
}
*/
pub fn print_err(err: &str) {
    println!("Error: {}", err.red());
}

pub fn read_file(mut file_name: &str) -> Option<String> {
    let mut file = match File::open(&mut file_name) {
        Ok(f) => f,
        Err(_) => {
            print_err(&format!("File \"{}\" not found", file_name));
            return None;
        }
    };
    let mut file_data = String::new();
    match file.read_to_string(&mut file_data) {
        Ok(_) => (),
        Err(_) => {
            print_err(&format!("Could not read data from file \"{}\"", file_name));
            return None;
        }
    };
    Some(file_data)
}
pub fn get_oas_value_version(file: &str) -> Option<(serde_json::Value, String)> {
    let swagger_str = match read_file(file) {
        Some(s) => s,
        None => {
            print_err(&format!("Failed at reading swagger file \"{}\"", file));
            return None;
        }
    };
    let swagger_value: serde_json::Value = if let Ok(s) = serde_json::from_str(&swagger_str) {
        s
    } else if let Ok(s) = serde_yaml::from_str::<serde_json::Value>(&swagger_str) {
        s
    } else {
        print_err(&format!("Failed at parsing swagger json file:\"{}\"", file));
        return None;
    };
    let version = swagger_value["openapi"]
        .to_string()
        .trim()
        .replace('\"', "");
    Some((swagger_value, version))
}
/*
pub fn parse_http(file_data: &str) -> Result<Vec<Session>, String> {
    let mut ret = vec![];
    let mut errors = String::new();
    match serde_json::from_str::<Vec<Log>>(file_data) {
        Ok(logs) => {
            for (i, s) in logs.iter().enumerate() {
                let mut session = vec![];
                for log in &s.session {
                    let mut headers1 = [httparse::EMPTY_HEADER; 24];
                    let mut req1 = httparse::Request::new(&mut headers1);
                    let req_payload = match req1.parse(log.request.as_bytes()) {
                        Ok(status) => match status {
                            Status::Complete(offset) => log.request[offset..].to_string(),
                            Status::Partial => {
                                println!("This request is a partial request:\n {:?}", req1);
                                continue;
                            }
                        },
                        Err(_) => {
                            errors += "Failed at parsing the request\n";
                            continue;
                        }
                    };
                    let mut req_headers = HashMap::new();
                    for h in req1.headers {
                        req_headers.insert(
                            h.name.to_string(),
                            match std::str::from_utf8(h.value) {
                                Ok(r) => r.to_string(),
                                Err(_) => {
                                    errors += "Failed at parsing request headers in the logs files";
                                    return Err(errors);
                                }
                            },
                        );
                    }
                    let path = match req1.path {
                        Some(r) => r.to_string(),
                        None => {
                            errors += "Failed at getting path from request in the logs files";
                            return Err(errors);
                        }
                    };
                    let method = match req1.method {
                        Some(r) => Method::method_from_str(r),
                        None => {
                            errors += "Failed at getting method from request in the logs files";
                            return Err(errors);
                        }
                    };
                    let req_query = match path.chars().position(|lf| lf == '?') {
                        Some(pos) => path[pos..].to_string(),
                        None => String::new(),
                    };
                    let mut headers2 = [httparse::EMPTY_HEADER; 24];
                    let mut res1 = httparse::Response::new(&mut headers2);
                    let res_payload = match res1.parse(log.response.as_bytes()) {
                        Ok(status) => match status {
                            Status::Complete(offset) => log.response[offset..].to_string(),
                            Status::Partial => {
                                println!("This response is a partial response:\n {:?}", res1);
                                continue;
                            }
                        },
                        Err(_) => {
                            errors += "Failed at parsing the response in the logs files\n";
                            continue;
                        }
                    };
                    let mut res_headers = HashMap::new();
                    for h in res1.headers {
                        res_headers.insert(
                            h.name.to_string(),
                            match std::str::from_utf8(h.value) {
                                Ok(r) => r.to_string(),
                                Err(_) => {
                                    errors +=
                                        "Failed at parsing response headers in the logs files";
                                    return Err(errors);
                                }
                            },
                        );
                    }
                    let status = match res1.code {
                        Some(r) => r,
                        None => {
                            errors += "Failed at getting status from response in the logs files";
                            return Err(errors);
                        }
                    };
                    session.push(ReqRes {
                        req_headers,
                        res_headers,
                        path,
                        method,
                        status,
                        req_payload,
                        res_payload,
                        req_query,
                    });
                }
                ret.push(Session {
                    token: i.to_string(),
                    req_res: session,
                });
            }
        }
        Err(_) => {
            errors += "Failed at prasing logs file into Vec<Logs>";
            return Err(errors);
        }
    }
    Ok(ret)
}
pub fn vec_sessions_parse(logs: &str) -> Result<Vec<Session>, String> {
    match serde_json::from_str::<Vec<Session>>(logs) {
        Ok(r) => Ok(r),
        Err(e0) => match serde_json::from_str::<Session>(logs) {
            Ok(r) => Ok(vec![r]),
            Err(e1) => {
                let err: String = format!("{}\n{}", e0,e1);
                Err(err)
            }
        },
    }
}
pub fn get_sessions(logs: &str) -> Vec<Session> {
    match (parse_http(logs), vec_sessions_parse(logs)) {
        (Ok(vec1), Ok(vec2)) => {
            if !vec1.is_empty() {
                vec1
            } else if !vec2.is_empty() {
                vec2
            } else {
                print_err("Failed parsing the logs");
                println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/cherrybomb/Documentation".purple());
                return vec![];
            }
        }
        (Ok(vec1), Err(e)) => {
            if !vec1.is_empty() {
                vec1
            } else {
                print_err(&format!("{}\n", e));
                print_err("Failed parsing the logs");
                println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/cherrybomb/Documentation".purple());
                return vec![];
            }
        }
        (Err(e), Ok(vec2)) => {
            if !vec2.is_empty() {
                vec2
            } else {
                print_err(&format!("{}\n", e));
                print_err("Failed parsing the logs");
                println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/cherrybomb/Documentation".purple());
                return vec![];
            }
        }
        (Err(e1), Err(e2)) => {
            print_err(&format!("{}\n", e1));
            print_err(&format!("{}\n", e2));
            print_err("Failed parsing the logs");
            println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/cherrybomb/Documentation".purple());
            return vec![];
        }
    }
}
pub fn parse_map_file(digest: Digest) -> Result<String, serde_json::Error> {
    let new_groups = digest
        .groups
        .iter()
        .map(|group| WebMapGroup {
            endpoints: group
                .endpoints
                .iter()
                .map(|ep| ep.path.path_ext.clone())
                .collect::<Vec<String>>(),
            links: group
                .links
                .iter()
                .map(|link| WebMapLink {
                    from: link.from.path.path_ext.clone(),
                    to: link.to.path.path_ext.clone(),
                    strength: link.strength,
                })
                .collect::<Vec<WebMapLink>>(),
        })
        .collect::<Vec<WebMapGroup>>();
    let map = WebMap {
        eps: digest.eps,
        groups: new_groups,
    };
    serde_json::to_string(&map)
}*/
pub fn write_to_file(file_name: &str, value: String) {
    match OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(file_name)
    {
        Ok(mut r) => match r.write_all(value.as_bytes()) {
            Ok(_) => (),
            Err(_) => {
                print_err(&format!("Failed writing to file \"{}\"", &file_name));
            }
        },
        Err(_) => {
            print_err(&format!("Failed creating \"{}\" file", &file_name));
        }
    };
}
