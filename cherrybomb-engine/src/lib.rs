pub mod config;
mod info;
mod scan;

use crate::config::Verbosity;
use crate::info::eps::EpTable;
use crate::info::params::ParamTable;
use crate::scan::active::active_scanner;
use crate::scan::active::http_client::auth::Authorization;
use cherrybomb_oas::legacy::legacy_oas::*;
use config::Config;
use scan::passive::passive_scanner;
use scan::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};


fn verbose_print(config: &Config, required: Option<Verbosity>, message: &str) {
    let required = required.unwrap_or(Verbosity::Normal);
    if config.verbosity >= required {
        println!("{message}");
    }
}

pub async fn run(config: &Config) -> anyhow::Result<Value> {
    verbose_print(config, None, "Starting Cherrybomb...");

    // Reading OAS file to string
    verbose_print(config, None, "Opening OAS file...");
    let f = config.file.clone();
    let mut ex = match f.into_os_string().into_string() {
        Ok(extension) => {
            extension.split(".").last().unwrap().to_owned()
            
        },
        Err(_) => todo!(),
    };
     println!("ext {ex}");
    let oas_file = match std::fs::read_to_string(&config.file) {
        Ok(file) => file,
        Err(e) => {
            return Err(anyhow::anyhow!("Error reading OAS file: {}", e));
        }
    };

    // Parsing OAS file to JSON
    verbose_print(config, None, "Parsing OAS file...");
    let oas_json: Value;
    let oas: OAS3_1;
    
    match ex.as_str() {
        "json" =>  {
            println!("Json");
            oas_json = match serde_json::from_str(&oas_file) {
               Ok(json) => json,
                Err(e) => {
                    return Err(anyhow::anyhow!("Error parsing OAS file: {}", e));
                }
            };
        },
        "yaml" => {
            println!("YAML");
            oas_json = match serde_yaml::from_str(&oas_file) {
                Ok(json) => json,
                Err(e) => {
                    return Err(anyhow::anyhow!("Error parsing OAS file: {}", e));
                }
            };
        },
        _ => {
            return Err(anyhow::anyhow!("Unsupported file extension: {}", ex));
        }
    }
    
    verbose_print(config, Some(Verbosity::Debug), "Creating OAS struct...");
    oas = match serde_json::from_value(oas_json.clone()) {
        Ok(oas) => oas,
        Err(e) => {
            return Err(anyhow::anyhow!("Error creating OAS struct: {}", e));
        }
    };
    match config.profile {
        config::Profile::Info => run_profile_info(&config, &oas, &oas_json),
        config::Profile::Normal => run_normal_profile(&config, &oas, &oas_json).await,
        config::Profile::Intrusive => todo!("Not implemented!"),
        config::Profile::Passive => run_passive_profile(&config, &oas, &oas_json),
        config::Profile::Full => run_full_profile(config, &oas, &oas_json).await,
    }
}

fn run_profile_info(config: &Config, oas: &OAS3_1, oas_json: &Value) -> anyhow::Result<Value> {
    // Creating parameter list
    verbose_print(config, None, "Creating param list...");
    let param_scan = ParamTable::new::<OAS3_1>(oas_json);
    let param_result: HashMap<&str, Value> = param_scan
        .params
        .iter()
        .map(|param| (param.name.as_str(), json!(param)))
        .collect();

    //Creating endpoint
    verbose_print(config, None, "Create endpoint list");
    let ep_table = EpTable::new::<OAS3_1>(oas_json);
    let endpoint_result: HashMap<&str, Value> = ep_table
        .eps
        .iter()
        .map(|param| (param.path.as_str(), json!(param)))
        .collect();

    verbose_print(config, None, "Creating report...");
    let report = json!({

        "params": param_result,
        "endpoints": endpoint_result,
    });
    Ok(report)
}

async fn run_active_profile(
    config: &Config,
    oas: &OAS3_1,
    oas_json: &Value,
) -> anyhow::Result<Value> {
    // Creating active scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating active scan struct...",
    );
    let mut active_scan = match active_scanner::ActiveScan::new(oas.clone(), oas_json.clone()) {
        Ok(scan) => scan,
        Err(e) => {
            return Err(anyhow::anyhow!("Error creating active scan struct: {}", e));
        }
    };

    // Running active scan
    verbose_print(config, None, "Running active scan...");
    let temp_auth = Authorization::None;
    active_scan
        .run(active_scanner::ActiveScanType::Full, &temp_auth)
        .await;
    let active_result: HashMap<&str, Vec<Alert>> = active_scan
        .checks
        .iter()
        .map(|check| (check.name(), check.inner()))
        .collect();
    let report = json!({ "active": active_result });
    Ok(report)
}

fn run_passive_profile(config: &Config, oas: &OAS3_1, oas_json: &Value) -> anyhow::Result<Value> {
    // Creating passive scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating passive scan struct...",
    );
    let mut passive_scan = passive_scanner::PassiveSwaggerScan {
        swagger: oas.clone(),
        swagger_value: oas_json.clone(),
        passive_checks: vec![], //TODO create check list from config
        verbosity: 0,
    };
    // Running passive scan
    verbose_print(config, None, "Running passive scan...");
    passive_scan.run(passive_scanner::PassiveScanType::Full);
    let passive_result: HashMap<&str, Vec<Alert>> = passive_scan
        .passive_checks
        .iter()
        .map(|check| (check.name(), check.inner()))
        .collect();
    Ok(json!({ "passive": passive_result }))
}

async fn run_normal_profile(
    config: &Config,
    oas: &OAS3_1,
    oas_json: &Value,
) -> anyhow::Result<Value> {
    let mut report = json!({});
    let mut results = HashMap::from([
        ("passive", run_passive_profile(config, oas, oas_json)),
        ("active", run_active_profile(config, oas, oas_json).await),
    ]);
    for (key, value) in results.iter_mut() {
        match value {
            Ok(result) => {
                if let Some(val) = result.get(key) {
                    report[key] = val.clone();
                }
            }
            Err(e) => {
                verbose_print(
                    config,
                    None,
                    &format!("WARNING: Error running {key} scan: {e}"),
                );
            }
        }
    }
    Ok(report)
}

async fn run_full_profile(config: &Config, oas: &OAS3_1, oas_json: &Value) -> anyhow::Result<Value> {
    let mut report = json!({});
    let mut results = HashMap::from([
        ("active", run_active_profile(config, oas, oas_json).await),
        ("passive", run_passive_profile(config, oas, oas_json)),
        ("params", run_profile_info(config, oas, oas_json)),
        ("endpoints", run_profile_info(config, oas, oas_json)),
    ]);
    for (key, value) in results.iter_mut() {
        match value {
            Ok(result) => {
                if let Some(val) = result.get(key) {
                    report[key] = val.clone();
                }
            }
            Err(e) => {
                verbose_print(
                    config,
                    None,
                    &format!("WARNING: Error running {} scan: {}", key, e),
                );
            }
        }
    }
    Ok(report)
}
