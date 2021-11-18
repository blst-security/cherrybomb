use mapper::*;
use digest::*;
use attacker::*;
use decider::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use url::{Url};
use colored::*;

fn read_file(file_name:&str) -> Option<String> {
    let mut file = match File::open(&format!("{}.json",file_name)) {
        Ok(f) => f,
        Err(_) => {
            println!("File \"{}\" not found", file_name);
            return None;
        },
    };
    let mut file_data = String::new();
    match file.read_to_string(&mut file_data) {
        Ok(_) => (),
        Err(_) => {
            println!("Could not read data from file \"{}\"", file_name);
            return None;
        },
    };
    Some(file_data)
}

fn get_sessions(logs:&str) -> Vec<Session> {
    match serde_json::from_str::<Vec<Session>>(logs) {
        Ok(r) => r,
        Err(_) => {
            match serde_json::from_str::<Session>(logs) {
                Ok(r) => {
                    vec![r]
                },
                Err(e) => {
                    println!("{}", e);
                    vec![]
                },
            }
        },
    }
}

fn write_map_file(file_name:String, map:String) {
    let mut map_file = OpenOptions::new().write(true).create(true).open(format!("{}.json", &file_name)).unwrap();
    map_file.write_all(map.as_bytes()).unwrap();
}

pub fn map(logs_file:String, output:String) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let mut digest = Digest::default();
    digest.load_vec_session(get_sessions(&logs));
    write_map_file(format!("{}", output), serde_json::to_string(&digest).unwrap());
}

pub async fn attack_domain(mut domain:String, map_file:String, decide_file:String, pop:usize, _gen:usize, verbosity:Verbosity) { // gen and pop
    let s_map = match read_file(&map_file){
        Some(r) => r,
        None => {
            return;
        }
    };
    let d_map:Digest = match serde_json::from_str(&s_map) {
        Ok(r) => r,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    match Url::parse(&domain) {
        Ok(_) => {
            if !(domain.contains("https://") || domain.contains("http://")) {
                domain.push_str("https://");
            }
        },
        Err(_) => {
            println!("Invalid domain \"{}\"", domain);
            return;
        },
    }
    let gen = 3;
    for _ in 0..gen {
        match attack(pop, verbosity, &decide_file).await {
            Ok(_) => {
                let vec_sessions = match read_file(&decide_file) {
                    Some(r) => r,
                    None => {
                        return;
                    }
                };
                let anomalys = decide(d_map.clone(), get_sessions(&vec_sessions), None);
                let mut a1 =vec![];
                let mut a2 =vec![];
                for a in &anomalys {
                    match a {
                        (Some(r),v) => {
                            a1.push(Some(r.clone()));
                            a2.push(v.clone());
                            match &r.endpoint {
                                Some(e) => {
                                    println!("{:?}", r.session.token);
                                    for ep in &r.session.req_res {
                                        if ep == e {
                                            println!("{:?}", (&serde_json::to_string(&ep).unwrap()).red()); 
                                        } else {
                                            println!("{:?}", (&serde_json::to_string(&ep).unwrap()).green());
                                        }
                                    }
                                },
                                None => {
                                    println!("{:?}", (&serde_json::to_string(&r.session).unwrap()).yellow());
                                } 
                            }
                        },
                        (None,v) => {
                            a1.push(None);
                            a2.push(v.clone());
                        },
                    }
                }
                refit(pop, a1, a2);
                //write_map_file(format!("{}.json", output), serde_json::to_string(&digest).unwrap());
            },
            Err(e) => {
                if e == "Unable to load attacker module, needs to be prepared first" {
                    //prepare(d_map.clone(), domain);
                }
            }
        }
    }
}

pub fn decide_sessions(decide_file:String) {
    let _logs = match read_file(&decide_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
}

pub fn load(logs_file:String, map_file:String) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let _map = match read_file(&map_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let mut digest:Digest = match serde_json::from_str(&map_file) {
        Ok(r) => r,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    digest.load_vec_session(get_sessions(&logs));
    write_map_file(format!("{}", map_file), serde_json::to_string(&digest).unwrap());
}
