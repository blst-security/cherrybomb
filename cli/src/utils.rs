use super::*;
use colored::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ClientReqRes {
    pub request: String,
    pub response: String,
}

pub fn print_err(err: &str) {
    println!("Error: {}", err.red());
}

pub fn read_file(file_name: &str) -> Option<String> {
    let mut file = match File::open(file_name) {
        Ok(f) => f,
        Err(_) => {
            print_err(&format!("File \"{file_name}\" not found"));
            return None;
        }
    };
    let mut file_data = String::new();
    match file.read_to_string(&mut file_data) {
        Ok(_) => (),
        Err(_) => {
            print_err(&format!("Could not read data from file \"{file_name}\""));
            return None;
        }
    };
    Some(file_data)
}
pub fn get_oas_value_version(file: &str) -> Option<(serde_json::Value, String)> {
    let swagger_str = match read_file(file) {
        Some(s) => s,
        None => {
            print_err(&format!("Failed at reading swagger file \"{file}\""));
            return None;
        }
    };
    let swagger_value: serde_json::Value = if let Ok(s) = serde_json::from_str(&swagger_str) {
        s
    } else if let Ok(s) = serde_yaml::from_str::<serde_json::Value>(&swagger_str) {
        s
    } else {
        print_err(&format!("Failed at parsing swagger json file:\"{file}\""));
        return None;
    };
    let version = swagger_value["openapi"]
        .to_string()
        .trim()
        .replace('\"', "");
    Some((swagger_value, version))
}

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
