use crate::options;
use crate::options::Options;
use anyhow::*;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, *};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs::File;
use std::io::Write;
use std::process::ExitCode;

#[derive(Clone, Copy)]
pub struct Colored {
    text: Color,
    level: Color,
    description: Color,
    location: Color,
    certainty: Color,
    severity_info: Color,
    severity_low: Color,
    severity_medium: Color,
    severity_high: Color,
    severity_critical: Color,
}
lazy_static! {
    pub static ref COLORS: Colored = Colored {
        text: Color::Grey,
        level: Color::Red,
        description: Color::Yellow,
        location: Color::Rgb {
            r: 255,
            g: 192,
            b: 203
        },
        certainty: Color::Blue,
        severity_info: Color::Green,
        severity_low: Color::Blue,
        severity_medium: Color::Rgb {
            r: 255,
            g: 255,
            b: 0
        },
        severity_high: Color::Rgb {
            r: 255,
            g: 165,
            b: 0
        },
        severity_critical: Color::Red,
    };
    pub static ref NO_COLORS: Colored = Colored {
        text: Color::White,
        level: Color::White,
        description: Color::White,
        location: Color::White,
        certainty: Color::White,
        severity_info: Color::White,
        severity_low: Color::White,
        severity_medium: Color::White,
        severity_high: Color::White,
        severity_critical: Color::White
    };
}

pub enum ColorChoice {
    WithColors(&'static Colored),
    NoColors(&'static Colored),
}

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

pub fn adjust_color(level: String, colors: &Colored) -> Cell {
    return match level.to_lowercase().as_str() {
        "info" => Cell::new(format!("{level:?}")).fg(colors.severity_info),
        "low" => Cell::new(format!("{level:?}")).fg(colors.severity_low),
        "medium" => Cell::new(format!("{level:?}")).fg(colors.severity_medium),
        "high" => Cell::new(format!("{level:?}")).fg(colors.severity_high),
        "high" => Cell::new(format!("{level:?}")).fg(colors.severity_high),
        &_ => Cell::new(format!("{level:?}")).fg(colors.text),
    };
}

pub fn print_tables(
    json_struct: Value,
    options: &Options,
    use_colors: bool,
) -> anyhow::Result<ExitCode> {
    let color_choice = if !use_colors {
        ColorChoice::WithColors(&COLORS)
    } else {
        ColorChoice::NoColors(&NO_COLORS)
    };
    let colors = match color_choice {
        ColorChoice::WithColors(c) => c,
        ColorChoice::NoColors(c) => c,
    };

    let mut status_vec = vec![];
    if let Some(json_struct) = json_struct["passive"].as_object() {
        status_vec.push(print_full_alert_table(
            json_struct,
            &options.format,
            &colors,
        )?);
        // print_alert_table(json_struct, &options.format, &colors)?;
    }
    if let Some(json_struct) = json_struct["active"].as_object() {
        status_vec.push(print_full_alert_table(
            json_struct,
            &options.format,
            colors,
        )?);
        // print_alert_table(json_struct, &options.format, &colors)?;
    }
    match options.format {
        options::OutputFormat::Table => {
            if let Some(json_struct) = json_struct["params"].as_object() {
                print_param_table(json_struct, &colors)?;
            }
            if let Some(json_struct) = json_struct["endpoints"].as_object() {
                print_endpoints_table(json_struct, &colors)?;
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

fn print_endpoints_table(json_struct: &Map<String, Value>, colors: &Colored) -> anyhow::Result<()> {
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
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .add_row(vec![
                    Cell::new(obj.path)
                        .add_attribute(Attribute::Bold)
                        .fg(colors.text),
                    Cell::new(to_format(&mut obj.res_params)).fg(colors.description),
                    Cell::new(to_format(&mut obj.statuses)).fg(colors.location),
                    Cell::new(to_format(&mut obj.ops)).fg(colors.severity_medium),
                    Cell::new(to_format(&mut obj.query_params)).fg(colors.severity_low),
                    Cell::new(to_format(&mut obj.headers_params)).fg(colors.severity_low),
                    Cell::new(to_format(&mut obj.req_body_params)).fg(colors.severity_low),
                ]);
        }
    }
    println!("{table}");
    Ok(())
}

fn print_alert_table(
    json_struct: &Map<String, Value>,
    output: &options::OutputFormat,
    colors: &Colored,
) -> anyhow::Result<CheckStatus> {
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
        if matches!(output, &options::OutputFormat::Table) {
            if let Some(alert) = alerts.get(0) {
                table
                    .load_preset(UTF8_FULL)
                    .apply_modifier(UTF8_ROUND_CORNERS)
                    .add_row(vec![
                        Cell::new(key)
                            .add_attribute(Attribute::Bold)
                            .fg(colors.text),
                        // Cell::new(format!("{:?}", alert.level)).fg(colors.level),
                        adjust_color(alert.level.to_string(), colors),
                        Cell::new(format!("{:?}", alerts.len())).fg(colors.level),
                        Cell::new(alert.description.clone()).fg(colors.description),
                    ]);
            }
        }
    }
    if matches!(output, &options::OutputFormat::Table) {
        println!("{table}");
    }
    Ok(return_status)
}
fn print_full_alert_table(
    json_struct: &Map<String, Value>,
    output: &options::OutputFormat,
    colors: &Colored,
) -> anyhow::Result<CheckStatus> {
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
        if matches!(output, &options::OutputFormat::Table) {
            alerts.iter().for_each(|alert| {
                table
                    .load_preset(UTF8_FULL)
                    .apply_modifier(UTF8_ROUND_CORNERS)
                    .add_row(vec![
                        Cell::new(key)
                            .add_attribute(Attribute::Bold)
                            .fg(colors.text),
                        Cell::new(format!("{:?}", alert.level)).fg(colors.level),
                        Cell::new(alert.description.clone()).fg(colors.description),
                        Cell::new(alert.location.clone()).fg(colors.location),
                    ]);
            });
        }
    }
    if matches!(output, &options::OutputFormat::Table) {
        println!("{table}");
    }
    Ok(return_status)
}
fn print_param_table(json_struct: &Map<String, Value>, colors: &Colored) -> anyhow::Result<()> {
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
                    Cell::new(key)
                        .add_attribute(Attribute::Bold)
                        .fg(colors.text),
                    Cell::new(obj.type_field).fg(colors.severity_info),
                    Cell::new(to_format(&mut obj.statuses)).fg(colors.location),
                    Cell::new(to_format(&mut obj.dms)).fg(colors.severity_medium),
                    Cell::new(to_format(&mut obj.eps)).fg(colors.severity_low),
                ]);
        }
    }

    println!("{table}");
    Ok(())
}
