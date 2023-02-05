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
use scan::checks::PassiveChecks;
use scan::*;
use scan::{checks::ActiveChecks, passive::passive_scanner};
use serde_json::{json, Value};
use std::collections::HashMap;
use strum::IntoEnumIterator;

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
    let oas_file = match std::fs::read_to_string(&config.file) {
        Ok(file) => file,
        Err(e) => {
            return Err(anyhow::anyhow!("Error reading OAS file: {}", e));
        }
    };

    // Parsing OAS file to JSON
    verbose_print(config, None, "Parsing OAS file...");
    let oas_json: Value = match serde_json::from_str(&oas_file) {
        Ok(json) => json,
        Err(e) => {
            return Err(anyhow::anyhow!("Error parsing OAS file: {}", e));
        }
    };

    // Parsing JSON to OAS struct
    verbose_print(config, Some(Verbosity::Debug), "Creating OAS struct...");
    let oas: OAS3_1 = match serde_json::from_value(oas_json.clone()) {
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

fn run_profile_info(config: &Config, _oas: &OAS3_1, oas_json: &Value) -> anyhow::Result<Value> {
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

    let new_vec_active = merge_active_checks(config);
    if !new_vec_active.is_empty() {
        return run_partial_active_profile(config, oas, oas_json, &new_vec_active).await;
    } else {
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
}

fn run_passive_profile(config: &Config, oas: &OAS3_1, oas_json: &Value) -> anyhow::Result<Value> {
    dbg!(&config.passive_exclude);
    // Creating passive scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating passive scan struct...",
    );

    let new_vec_of_passive = merge_passive_checks(config); //contains vec check without exclude
    if !new_vec_of_passive.is_empty() {
        //if there is exclude passive checks so run partial function
        run_partial_passive_profile(config, oas, oas_json, &new_vec_of_passive)
    } else {
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

async fn run_full_profile(
    config: &Config,
    oas: &OAS3_1,
    oas_json: &Value,
) -> anyhow::Result<Value> {
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
fn merge_passive_checks(config: &Config) -> Vec<PassiveChecks> {
    // function for passive profile
    let mut passive_checks = vec![];
    let all_checks: Vec<PassiveChecks> = PassiveChecks::iter().collect();
    if !config.passive_exclude.is_empty() && !config.passive_include.is_empty() {
        // can not be set both exluce and include
        panic!("Only exclude or include can be set");
    }
    if !config.passive_exclude.is_empty() {
        // exclude passive checks
        passive_checks = all_checks
            .iter()
            .filter(|x| !config.passive_exclude.contains(&x.name().to_string()))
            .cloned()
            .collect();
    }

    passive_checks
}

fn merge_active_checks(config: &Config) -> Vec<ActiveChecks> {
    // function for passive profile
    dbg!(&config.active_exclude);
    let mut active_checks: Vec<ActiveChecks> = vec![];
    let all_checks: Vec<ActiveChecks> = ActiveChecks::iter().collect();
    if !config.active_exclude.is_empty() && !config.active_include.is_empty() {
        // can not be set both exluce and include
        panic!("Only exclude or include can be set");
    }
    if !config.active_exclude.is_empty() {
        // exclude passive checks
        active_checks = all_checks
            .iter()
            .filter(|x| !config.active_exclude.contains(&x.name().to_string()))
            .cloned()
            .collect();
    }

    active_checks
}

fn run_partial_passive_profile(
    config: &Config,
    oas: &OAS3_1,
    oas_json: &Value,
    vec_passive: &Vec<PassiveChecks>,
) -> anyhow::Result<Value> {
    // Creating passive scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating passive scan struct...",
    );
    let mut passive_scan = passive_scanner::PassiveSwaggerScan {
        swagger: oas.clone(),
        swagger_value: oas_json.clone(),
        passive_checks: vec_passive.to_vec(), //TODO create check list from config
        verbosity: 0,
    };

    // Running passive scan
    verbose_print(config, None, "Running passive scan...");
    passive_scan.run(passive_scanner::PassiveScanType::Partial(
        vec_passive.to_vec(),
    ));
    let passive_result: HashMap<&str, Vec<Alert>> = passive_scan
        .passive_checks
        .iter()
        .map(|check| (check.name(), check.inner()))
        .collect();
    Ok(json!({ "passive": passive_result }))
}
async fn run_partial_active_profile(
    config: &Config,
    oas: &OAS3_1,
    oas_json: &Value,
    vec_active: &Vec<ActiveChecks>,
) -> anyhow::Result<Value> {
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
        .run(
            active_scanner::ActiveScanType::Partial(vec_active.to_vec()),
            &temp_auth,
        )
        .await;
    let active_result: HashMap<&str, Vec<Alert>> = active_scan
        .checks
        .iter()
        .map(|check| (check.name(), check.inner()))
        .collect();
    let report = json!({ "active": active_result });
    Ok(report)
}
