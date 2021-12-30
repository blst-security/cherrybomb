use super::*;
use attacker::*;
use colored::*;
use decider::*;
use httparse::Status;
use mapper::digest::*;
use mapper::*;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
struct ClientReqRes {
    request: String,
    response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
struct Log {
    session: Vec<ClientReqRes>,
}

#[derive(Debug, Clone, Serialize)]
struct WebMapLink {
    from: String,
    to: String,
    strength: u64,
}

#[derive(Debug, Clone, Serialize)]
struct WebMapGroup {
    endpoints: Vec<String>,
    links: Vec<WebMapLink>,
}

#[derive(Debug, Clone, Serialize)]
struct WebMap {
    eps: Vec<Endpoint>,
    groups: Vec<WebMapGroup>,
}

fn print_err(err: &str) {
    println!("Error: {}", err.red());
}

fn read_file(mut file_name: &str) -> Option<String> {
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

fn parse_http(file_data: &str) -> Result<Vec<Session>, String> {
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
                        Some(r) => Method::from_str(r),
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

fn vec_sessions_parse(logs: &str) -> Result<Vec<Session>, String> {
    match serde_json::from_str::<Vec<Session>>(logs) {
        Ok(r) => Ok(r),
        Err(e0) => match serde_json::from_str::<Session>(logs) {
            Ok(r) => Ok(vec![r]),
            Err(e1) => {
                let mut err: String = format!("{}", e0);
                err += &format!("\n{}", e1);
                Err(err)
            }
        },
    }
}

fn get_sessions(logs: &str) -> Vec<Session> {
    match (parse_http(logs), vec_sessions_parse(logs)) {
        (Ok(vec1), Ok(vec2)) => {
            if !vec1.is_empty() {
                vec1
            } else if !vec2.is_empty() {
                vec2
            } else {
                print_err("Failed parsing the logs");
                println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/firecracker/Documentation".purple());
                return vec![];
            }
        }
        (Ok(vec1), Err(e)) => {
            if !vec1.is_empty() {
                vec1
            } else {
                print_err(&format!("{}\n", e));
                print_err("Failed parsing the logs");
                println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/firecracker/Documentation".purple());
                return vec![];
            }
        }
        (Err(e), Ok(vec2)) => {
            if !vec2.is_empty() {
                vec2
            } else {
                print_err(&format!("{}\n", e));
                print_err("Failed parsing the logs");
                println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/firecracker/Documentation".purple());
                return vec![];
            }
        }
        (Err(e1), Err(e2)) => {
            print_err(&format!("{}\n", e1));
            print_err(&format!("{}\n", e2));
            print_err("Failed parsing the logs");
            println!("{} {}", "Ran into an error while parsing your logs".red(), "you can check out the correct formats in this address: https://www.blstsecurity.com/firecracker/Documentation".purple());
            return vec![];
        }
    }
}

fn parse_map_file(digest: Digest) -> Result<String, serde_json::Error> {
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
}

fn write_map_file(file_name: String, map: String) {
    match OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("{}.json", &file_name))
    {
        Ok(mut r) => match r.write_all(map.as_bytes()) {
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

pub fn add_token(token: String) -> bool {
    match Uuid::parse_str(&token) {
        Ok(_) => {
            match OpenOptions::new()
                .write(true)
                .create(true)
                .open(format!("{}.txt", "token"))
            {
                Ok(mut r) => match r.write_all(token.as_bytes()) {
                    Ok(_) => true,
                    Err(_) => {
                        print_err("Failed writing token to file");
                        false
                    }
                },
                Err(_) => {
                    print_err("Failed to create token file");
                    false
                }
            }
        }
        Err(e) => {
            print_err(&format!("Invalid token, {:?}", e));
            false
        }
    }
}

pub fn map(logs_file: String, output: String) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            print_err(&format!("Failed reading logs file \"{}\"", &logs_file));
            return;
        }
    };
    let mut digest = Digest::default();
    let sessions = get_sessions(&logs);
    if !sessions.is_empty() {
        println!("{}", "Starts mapping...".green());
        digest.load_vec_session(sessions);
        let map_string = match serde_json::to_string(&digest) {
            Ok(r) => r,
            Err(_) => {
                print_err("Failed parsing digest");
                return;
            }
        };
        write_map_file(format!("{}_checkpoint", output), map_string);
        write_map_file(
            output.clone(),
            parse_map_file(digest).unwrap_or_else(|_| {
                print_err("Failed parsing digest into web map");
                String::new()
            }),
        );
        println!("{}", format!("Mapping Done! Saved as \"{}.json\", you can upload and view it at https://www.blstsecurity.com/firecracker/Visualizer", output).green());
    } else {
        print_err("Something went wrong while mapping, check the errors above");
    }
}

pub fn prepare_attacker(mut url: String, map_file: String) {
    let d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    match Url::parse(&url) {
        Ok(_) => {
            if !(url.contains("https://") || url.contains("http://")) {
                url.push_str("https://");
            }
        }
        Err(_) => {
            print_err(&format!("Invalid url \"{}\"", url));
            return;
        }
    }
    let groups = prepare(d_map, url);
    for (i, g) in groups.iter().enumerate() {
        println!("Population number {:?} , endpoints: {:?}", i, g);
    }
}

pub async fn attack_domain(
    map_file: String,
    decide_file: String,
    pop: usize,
    gen: usize,
    verbosity: Verbosity,
    headers: Vec<Header>,
    auth: Authorization,
) {
    let d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    println!("{}", "Attacking...".purple().bold());
    for _ in 0..gen {
        println!("{}", format!("Generation: {}", gen).purple().bold());
        match attack(
            pop,
            verbosity,
            &format!("{}.json", decide_file),
            &headers,
            &auth,
        )
        .await
        {
            Ok(vec_sessions) => {
                let anomalys = decide(d_map.clone(), vec_sessions, None);
                let mut a1 = vec![];
                let mut a2 = vec![];
                println!("{}", "Decider starting\nSearching for anomalys...".bold());
                for a in &anomalys {
                    match a {
                        (Some(r), v) => {
                            a1.push(Some(r.clone()));
                            a2.push(v.clone());
                            let anomaly_score: u16 = v.iter().sum();
                            println!("Anomaly score: {}", anomaly_score.to_string().bold());
                            match &r.endpoint {
                                Some(e) => {
                                    println!("{:?}", r.session.token);
                                    for ep in &r.session.req_res {
                                        if ep == e {
                                            println!("{}", format!("{}", ep).red());
                                        } else {
                                            println!("{}", format!("{}", ep).green());
                                        }
                                    }
                                }
                                None => {
                                    println!(
                                        "{}",
                                        (&serde_json::to_string(&r.session).unwrap()).yellow()
                                    );
                                }
                            }
                        }
                        (None, v) => {
                            a1.push(None);
                            a2.push(v.clone());
                        }
                    }
                }
                refit(pop, a1, a2);
                println!("{}", "Decider done!".bold());
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    }
    println!("{}", "Attcker done!".purple().bold());
}

pub fn decide_sessions(logs_file: String, map_file: String) {
    let vec_sessions = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            print_err(&format!("Failed reading logs file \"{}\"", &logs_file));
            return;
        }
    };
    let d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    let anomalys = decide(d_map, get_sessions(&vec_sessions), None);
    let mut a1 = vec![];
    let mut a2 = vec![];
    println!("{}", "Decider starting\nSearching for anomalys...".bold());
    for a in &anomalys {
        match a {
            (Some(r), v) => {
                a1.push(Some(r.clone()));
                a2.push(v.clone());
                let anomaly_score: u16 = v.iter().sum();
                println!("Anomaly score: {}", anomaly_score.to_string().bold());
                match &r.endpoint {
                    Some(e) => {
                        println!("{:?}", r.session.token);
                        for ep in &r.session.req_res {
                            if ep == e {
                                println!("{}", format!("{}", ep).red());
                            } else {
                                println!("{}", format!("{}", ep).green());
                            }
                        }
                    }
                    None => {
                        println!("{}", (&serde_json::to_string(&r.session).unwrap()).yellow());
                    }
                }
            }
            (None, v) => {
                a1.push(None);
                a2.push(v.clone());
            }
        }
    }
    println!("{}", "Decider done!".bold());
}

pub fn load(logs_file: String, map_file: String) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            print_err(&format!("Failed reading logs file \"{}\"", &logs_file));
            return;
        }
    };
    let mut d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    let sessions = get_sessions(&logs);
    if !sessions.is_empty() {
        println!("{}", "Starts mapping...".green());
        d_map.load_vec_session(sessions);
        let map_string = match serde_json::to_string(&d_map) {
            Ok(r) => r,
            Err(_) => {
                print_err("Failed parsing digest");
                return;
            }
        };
        write_map_file(format!("{}_checkpoint", map_file), map_string);
        write_map_file(
            map_file.clone(),
            parse_map_file(d_map).unwrap_or_else(|_| {
                print_err("Failed parsing digest into web map");
                String::new()
            }),
        );
        println!("{}", format!("Mapping Done! Saved as \"{}.json\", you can upload and view it at https://www.blstsecurity.com/firecracker/Visualizer", map_file).green());
    } else {
        print_err("Something went wrong while mapping, check the errors above");
    }
}
