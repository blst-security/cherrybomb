use crate::options;
use crate::options::Options;
use anyhow::*;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, *};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs::File;
use std::io::Write;
use std::option;
use std::process::ExitCode;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableAlert {
    pub certainty: String,
    pub description: String,
    pub level: String,
    pub location: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableParam {
    pub children: Vec<String>,
    pub dms: Vec<String>,
    pub eps: Vec<String>,
    pub max: Value,
    pub min: Value,
    pub name: String,
    pub parents: Vec<String>,
    pub statuses: Vec<String>,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]

pub struct TableEP {
    pub path: String,
    //urls
    servers: Vec<String>,
    pub ops: Vec<String>,
    pub query_params: Vec<String>,
    pub headers_params: Vec<String>,
    pub req_body_params: Vec<String>,
    pub res_params: Vec<String>,
    pub statuses: Vec<String>,
}

fn to_format(vec_raw: &mut Vec<String>) -> String {
    vec_raw.dedup();
    vec_raw
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(", ")
}

#[derive(PartialEq)]
enum CheckStatus {
    OK,
    Warning,
    Fail,
}

pub fn print_tables(json_struct: Value, options: &Options) -> anyhow::Result<ExitCode> {
    let mut status_vec = vec![];

    match options.format {
        options::OutputFormat::Table => {
            if let Some(json_struct) = json_struct["passive"].as_object() {
                status_vec.push(print_full_alert_table(json_struct)?);
                //create_table_with_full_verbosity(&json_struct)?;
            }
            if let Some(json_struct) = json_struct["active"].as_object() {
                status_vec.push(print_full_alert_table(json_struct)?);
            }

            if let Some(json_struct) = json_struct["params"].as_object() {
                print_param_table(json_struct)?;
            }
            if let Some(json_struct) = json_struct["endpoints"].as_object() {
                print_endpoints_table(json_struct)?;
            }
        }
        options::OutputFormat::Json => {
            println!("{}", json_struct);
            if let Some(output_file) = &options.output {
                let mut file = File::create(output_file)?;
                file.write_all(json_struct.to_string().as_bytes())?;
            }
        }
    }
    if status_vec.contains(&CheckStatus::Fail) {
        Ok(ExitCode::from(101))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn print_endpoints_table(json_struct: &Map<String, Value>) -> anyhow::Result<()> {
    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_FULL)
        .apply_modifier(modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "Path",
            "Response Params",
            "Statuses",
            "Delivery Method",
            "Query Params",
            "Headers Params",
            "Body Params",
        ]);

    for (_, val) in json_struct {
        let jsn: Option<TableEP> = serde_json::from_value(val.clone())?;

        if let Some(mut obj) = jsn {
            // dbg!(&val);
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .add_row(vec![
                    Cell::new(obj.path).add_attribute(Attribute::Bold),
                    Cell::new(to_format(&mut obj.res_params)),
                    Cell::new(to_format(&mut obj.statuses)),
                    Cell::new(to_format(&mut obj.ops)),
                    Cell::new(to_format(&mut obj.query_params)),
                    Cell::new(to_format(&mut obj.headers_params)),
                    Cell::new(to_format(&mut obj.req_body_params)),
                ]);
        }
    }
    println!("{table}");
    Ok(())
}

fn print_param_table(json_struct: &Map<String, Value>) -> anyhow::Result<()> {
    //create a parameter table
    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_FULL)
        .apply_modifier(modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "Name",
            "Type",
            "Statuses",
            "Delivery Method",
            "Endpoints",
        ]);

    for (key, val) in json_struct {
        let jsn: Option<TableParam> = serde_json::from_value(val.clone())?;
        if let Some(mut obj) = jsn {
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .add_row(vec![
                    Cell::new(key).add_attribute(Attribute::Bold),
                    Cell::new(obj.type_field),
                    Cell::new(to_format(&mut obj.statuses)),
                    Cell::new(to_format(&mut obj.dms)),
                    Cell::new(to_format(&mut obj.eps)),
                ]);
        }
    }

    println!("{table}");
    Ok(())
}

fn print_alert_table(json_struct: &Map<String, Value>) -> anyhow::Result<CheckStatus> {
    //display simple table  with alerts
    let mut table = Table::new();
    let mut return_status = CheckStatus::OK;
    table
        .load_preset(presets::UTF8_FULL)
        .apply_modifier(modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Check", "Severity", "Alerts", "Description"]);
    for (key, val) in json_struct {
        //checks name and vec of alerts
        let alerts: Vec<TableAlert> = serde_json::from_value(val.clone())?;
        if !alerts.is_empty() {
            return_status = CheckStatus::Fail;
        }
        if let Some(alert) = alerts.get(0) {
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .add_row(vec![
                    Cell::new(key).add_attribute(Attribute::Bold),
                    Cell::new(format!("{:?}", alert.level)),
                    Cell::new(format!("{:?}", alerts.len())),
                    Cell::new(alert.description.clone()),
                ]);
        }
    }
    println!("{table}");

    Ok(return_status)
}

fn print_full_alert_table(json_struct: &Map<String, Value>) -> anyhow::Result<CheckStatus> {
    //create a table of alerts with full verbosity
    let mut table = Table::new();
    let mut return_status = CheckStatus::OK;
    table
        .load_preset(presets::UTF8_FULL)
        .apply_modifier(modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Check", "Severity", "Description", "Location"]);
    for (key, val) in json_struct {
        //checks name and vec of alerts
        let alerts: Vec<TableAlert> = serde_json::from_value(val.clone())?;
        if !alerts.is_empty() {
            return_status = CheckStatus::Fail;
        }
        alerts.iter().for_each(|alert| {
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .add_row(vec![
                    Cell::new(key).add_attribute(Attribute::Bold),
                    Cell::new(format!("{:?}", alert.level)),
                    Cell::new(alert.description.clone()),
                    Cell::new(alert.location.clone()),
                ]);
        });
    }
    println!("{table}");

    Ok(return_status)
}
