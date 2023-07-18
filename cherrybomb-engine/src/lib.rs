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
use scan::checks::{ActiveChecks, PassiveChecks};
use scan::passive::passive_scanner;
use scan::*;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::vec;
use strum::IntoEnumIterator;

fn verbose_print(config: &Config, required: Option<Verbosity>, message: &str) {
    let required = required.unwrap_or(Verbosity::Normal);
    if config.verbosity >= required {
        println!("{message}");
    }
}
//take config and return hashset of checks to remove
fn merge_config_exclude(config: &Config, mut checks: HashSet<String>) -> HashSet<String> {
    if !config.passive_exclude.is_empty() {
        for passive_check in config.passive_exclude.iter() {
            checks.remove(passive_check);
        }
    }

    if !config.active_exclude.is_empty() {
        for active_check in config.active_exclude.iter() {
            checks.remove(active_check);
        }
    }
    checks.clone()
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
        config::Profile::Active => {
            if !&config.passive_include.is_empty() {
                let mut n_config = config.clone();
                let mut vec_passive: Vec<String> = PassiveChecks::iter()
                    .map(|x| x.name().to_string())
                    .collect();
                vec_passive.retain(|check| !config.passive_include.contains(check));
                n_config.passive_exclude = vec_passive;
                run_normal_profile(&n_config, &oas, &oas_json).await
            } else {
                run_active_profile(&config, &oas, &oas_json).await
            }
        }

        config::Profile::Passive => {
            if !&config.active_include.is_empty() {
                let mut n_config = config.clone();
                let mut vec_active: Vec<String> =
                    ActiveChecks::iter().map(|x| x.name().to_string()).collect();
                vec_active.retain(|check| !config.active_include.contains(check));
                n_config.active_exclude = vec_active;
                run_normal_profile(&n_config, &oas, &oas_json).await
            } else {
                run_passive_profile(&config, &oas, &oas_json)
            }
        }
        config::Profile::Full => run_full_profile(config, &oas, &oas_json).await,
    }
    //into the match  add include test into passive and active, so just create a json with passive and active
    //return manually
    //modify the config.exclude by the difference between include to all others test.
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
    let checks = merge_config_exclude(
        config,
        ActiveChecks::iter().map(|x| x.name().to_string()).collect(),
    );
    let active_checks: Vec<ActiveChecks> = ActiveChecks::iter()
        .filter(|check| checks.contains(check.name()))
        .collect();
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
            active_scanner::ActiveScanType::Partial(active_checks),
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

fn run_passive_profile(config: &Config, oas: &OAS3_1, oas_json: &Value) -> anyhow::Result<Value> {
    // Creating passive scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating passive scan struct...",
    );
    //create hashsetand excluding checks
    let checks = merge_config_exclude(
        config,
        PassiveChecks::iter()
            .map(|x| x.name().to_string())
            .collect(),
    );
    //create vector of passive checks to run
    let passive_checks = PassiveChecks::iter()
        .filter(|check| checks.contains(check.name()))
        .collect();
    let mut passive_scan = passive_scanner::PassiveSwaggerScan {
        swagger: oas.clone(),
        swagger_value: oas_json.clone(),
        passive_checks: vec![], //TODO create check list from config
        verbosity: 0,
    };
    // Running passive scan
    verbose_print(config, None, "Running passive scan...");
    passive_scan.run(passive_scanner::PassiveScanType::Partial(passive_checks));
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
