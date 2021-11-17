use mapper::*;
use digest::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use url::{Url};

fn read_file(mut file_name:String) -> Option<String> {
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
            println!("{}", e);
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
    let mut map_file = OpenOptions::new().write(true).create(true).open(&file_name).unwrap();
    map_file.write_all(map.as_bytes()).unwrap();
}

pub fn map(logs_file:String, output:String) {
    let logs = match read_file(logs_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let mut digest = Digest::default();
    digest.load_vec_session(get_sessions(&logs));
    write_map_file(format!("{}.json", output), serde_json::to_string(&digest).unwrap());
}

pub fn attack(domain:String, map_file:String, _decide_file:String) {
    let map = match read_file(format!("{}.json",map_file)) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let _map:Digest = serde_json::from_str(&map).unwrap();
    match Url::parse(&domain) {
        Ok(_) => (),
        Err(_) => {
            println!("Invalid domain \"{}\"", domain);
            return;
        },
    }
    // attack
    // write_map_file(format!("{}.json", output), serde_json::to_string(&digest).unwrap());
}

pub fn decide(decide_file:String) {
    let _logs = match read_file(decide_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    // send refit to the attacker (talk with guy)
}

pub fn load(logs_file:String, map_file:String) {
    let logs = match read_file(logs_file) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let map = match read_file(map_file.clone()) {
        Some(r) => r,
        None => {
            return;
        }
    };
    let mut digest:Digest = match serde_json::from_str(&map) {
        Ok(r) => r,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    digest.load_vec_session(get_sessions(&logs));
    write_map_file(format!("{}", map_file), serde_json::to_string(&digest).unwrap());
}
