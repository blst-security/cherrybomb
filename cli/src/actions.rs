use mapper::*;
use digest::*;
use attacker::*;
use decider::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use url::{Url};
use colored::*;

fn read_file(mut file_name:&str) -> Option<String> {
    let mut file = match File::open(&mut file_name) {
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
        Err(e) => {
            println!("{:?}",e);
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

pub fn prepare_attacker(mut url:String, map_file:String) {
    let s_map = match read_file(&format!("{}.json", map_file)){
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
    match Url::parse(&url) {
        Ok(_) => {
            if !(url.contains("https://") || url.contains("http://")) {
                url.push_str("https://");
            }
        },
        Err(_) => {
            println!("Invalid url \"{}\"", url);
            return;
        },
    }
    let groups = prepare(d_map.clone(), url);
    for (i, g) in groups.iter().enumerate() {
        println!("Population number {:?} , endpoints: {:?}" , i, g);
    }
}

pub async fn attack_domain(map_file:String, decide_file:String, pop:usize, gen:usize, verbosity:Verbosity) { // gen and pop
    let s_map = match read_file(&format!("{}.json", map_file)){
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
    for _ in 0..gen {
        match attack(pop, verbosity, &format!("{}.json", decide_file)).await {
            Ok(vec_sessions) => {
                let anomalys = decide(d_map.clone(), vec_sessions, None);
                let mut a1 = vec![];
                let mut a2 = vec![];
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
                println!("Done!");
            },
            Err(e) => {
                println!("{}", e);
            }
        }
    }
}

pub fn decide_sessions(logs_file:String, map_file:String) {
    let vec_sessions = match read_file(&format!("{}", logs_file)) {
        Some(r) => r,
        None => {
            return;
        }
    }; 
    let s_map = match read_file(&format!("{}.json", map_file)){
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
    let anomalys = decide(d_map.clone(), get_sessions(&vec_sessions), None);
    let mut a1 = vec![];
    let mut a2 = vec![];
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
}

pub fn load(logs_file:String, map_file:String) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let _map = match read_file(&format!("{}.json", map_file)) {
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