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
use serde_yaml;
use anyhow::anyhow;

fn verbose_print(config: &Config, required: Option<Verbosity>, message: &str) {
    let required = required.unwrap_or(Verbosity::Normal);
    if config.verbosity >= required {
        println!("{message}");
    }
}

pub async fn run(config: &mut Config) -> anyhow::Result<Value> {
    verbose_print(config, None, "Starting Cherrybomb...");
    verbose_print(config, None, "Opening OAS file...");

    let (oas,oas_json) = if let Some(ext)= config.file.extension(){
        verbose_print(config, None, "Reading OAS file...");
        let oas_file = match std::fs::read_to_string(&config.file) {
            Ok(file) => file,
            Err(e) => return Err(anyhow::Error::msg(format!("Error opening OAS file: {}", e))),
        };
        let oas_json: Value = match ext.to_str() {
            Some("json") => {
                verbose_print(config, None, "Parsing OAS file...");
                match serde_json::from_str(&oas_file) {
                    Ok(json) => json,
                    Err(e) => return Err(anyhow::Error::msg(format!("Error parsing OAS file: {}", e))),
                }
            }
            Some("yaml") | Some("yml") => {
                verbose_print(config, None, "Parsing OAS file...");
                match serde_yaml::from_str(&oas_file) {
                    Ok(yaml) => yaml,
                    Err(e) => return Err(anyhow::Error::msg(format!("Error parsing OAS file: {}", e))),
                }
            }
            _ => return Err(anyhow::Error::msg("Unsupported config file extension")),
        };
        let oas: OAS3_1 = match serde_json::from_value(oas_json.clone().into()) {
            Ok(oas) => oas,
            Err(e) => return Err(anyhow::Error::msg(format!("Error creating OAS struct: {}", e))),
        };
        (oas,oas_json)
    }else {
        return Err(anyhow!("Misconfigured file extention"));
    };
    match config.profile {
        config::Profile::Info => run_profile_info(&config, &oas, &oas_json),
        config::Profile::Normal => run_normal_profile(config, &oas, &oas_json).await,
        config::Profile::Active => {
            if !&config.passive_include.is_empty() {
                config.passive_checks = config.passive_include.clone(); //passive include into passive checks
                run_normal_profile(config, &oas, &oas_json).await
            } else {
                run_active_profile(config, &oas, &oas_json).await
            }
        }

        config::Profile::Passive => {
            if !&config.active_include.is_empty() {
                config.active_checks = config.active_include.clone();
                run_normal_profile(config, &oas, &oas_json).await
            } else {
                run_passive_profile(config, &oas, &oas_json)
            }
        }
        config::Profile::Full => run_full_profile(config, &oas, &oas_json).await,
        config::Profile::OWASP => todo!("not implemented yet!"),
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
    config: &mut Config,
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
    let temp_auth = config.get_auth();
    let active_result: HashMap<&str, Vec<Alert>> = match config.active_checks.is_empty() {
        true => {
            // if empty, active profile and exclude_active checks is set
            //create a vec of active scan checks

            let all_active_checks = ActiveChecks::iter().map(|x| x.name().to_string()).collect();
            config.update_checks_active(all_active_checks);

            //create a vec of active scan checks
            let active_checks = ActiveChecks::create_checks(&config.active_checks);

            active_scan
                .run(
                    active_scanner::ActiveScanType::Partial(active_checks),
                    &temp_auth,
                )
                .await;
            active_scan
                .checks
                .iter()
                .map(|check| (check.name(), check.inner()))
                .collect()
        }
        false => {
            // if the active_checks not empty, active include_checks and passive profile is set

            // let active_checks_to_run = ActiveChecks::iter()
            //     .filter(|check| config.active_checks.contains(&check.name().to_string()))
            //     .collect();
            let active_checks_to_run = ActiveChecks::create_checks(&config.active_checks.clone()); //create active check vec
            active_scan
                .run(
                    active_scanner::ActiveScanType::Partial(active_checks_to_run),
                    &temp_auth,
                )
                .await;
            active_scan
                .checks
                .iter()
                .map(|check| (check.name(), check.inner()))
                .collect()
        }
    };

    Ok(json!({ "active": active_result }))
}

fn run_passive_profile(
    config: &mut Config,
    oas: &OAS3_1,
    oas_json: &Value,
) -> anyhow::Result<Value> {
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating passive scan struct...",
    );
    // Creating passive scan struct
    let mut passive_scan = passive_scanner::PassiveSwaggerScan {
        swagger: oas.clone(),
        swagger_value: oas_json.clone(),
        passive_checks: vec![],
        verbosity: 0,
    };

    // Running passive scan
    verbose_print(config, None, "Running passive scan...");

    let passive_result: HashMap<&str, Vec<Alert>> = match config.passive_checks.is_empty() {
        true => {
            // if passive_checks empty, passive profile and exclude passive checks is set
            let all_passive_checks = PassiveChecks::iter()
                .map(|x| x.name().to_string())
                .collect(); //collect all passive checks
            config.update_checks_passive(all_passive_checks);

            //create vector of passive checks to run

            // let passive_checks_to_run = PassiveChecks::iter()
            //     .filter(|check| config.active_checks.contains(&check.name().to_string()))
            //     .collect();

            let passive_checks_to_run = PassiveChecks::create_checks(&config.passive_checks);
            passive_scan.run(passive_scanner::PassiveScanType::Partial(
                passive_checks_to_run,
            ));
            passive_scan
                .passive_checks
                .iter()
                .map(|check| (check.name(), check.inner()))
                .collect()
        }
        false => {
            // if the passive_checks not empty, so passive include_checks and active profile is set

            // let passive_checks_to_run = PassiveChecks::iter()
            //     .filter(|check| config.passive_checks.contains(&check.name().to_string()))
            //     .collect(); //create vec of passive checks

            let passive_checks_to_run = PassiveChecks::create_checks(&config.passive_checks);
            passive_scan.run(passive_scanner::PassiveScanType::Partial(
                passive_checks_to_run,
            ));
            passive_scan
                .passive_checks
                .iter()
                .map(|check| (check.name(), check.inner()))
                .collect()
        }
    };
    Ok(json!({"passive": passive_result}))
}

async fn run_normal_profile(
    config: &mut Config,
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
    config: &mut Config,
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
