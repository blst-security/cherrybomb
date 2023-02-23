pub mod config;
mod info;
mod scan;

use std::collections::{HashMap, HashSet};
use serde_json::{json, Value};
use strum::IntoEnumIterator;
use config::{Config, Verbosity};
use info::{eps::EpTable, params::ParamTable};
use scan::*;
use scan::checks::{PassiveChecks, ActiveChecks};
use scan::active::{active_scanner, http_client::auth::Authorization};
use scan::passive::passive_scanner;
use cherrybomb_oas::legacy::legacy_oas::*;

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

    // Creating checks lists
    let mut checks : HashMap<&str,HashSet<&str>> = HashMap::new();
    match config.profile {
        config::Profile::Info => {
            checks.insert("info",HashSet::new());
            checks.insert("active",HashSet::new());
            checks.insert("passive",HashSet::new())
    },
        config::Profile::Normal => {
            checks.insert("passive",PassiveChecks::iter().map(|x| x.name()).collect());
            checks.insert("active",ActiveChecks::iter().map(|x| x.name()).collect())
        },
        config::Profile::Intrusive => todo!("Not implemented!"),
        config::Profile::Passive => {
            checks.insert("passive",PassiveChecks::iter().map(|x| x.name()).collect());
            checks.insert("active",HashSet::new())

        },
        config::Profile::Full => {
            checks.insert("info",HashSet::new());
            checks.insert("passive",PassiveChecks::iter().map(|x| x.name()).collect());
            checks.insert("active",ActiveChecks::iter().map(|x| x.name()).collect())
        },
    };
    dbg!(&config.active_exclude);
    dbg!(&config.active_include);
    dbg!(&config.passive_exclude);
    dbg!(&config.passive_include);
    for active_check in config.active_exclude.iter() {
         if let Some(a) = checks.get_mut("active") {
             a.remove(active_check.as_str());
        }
    }
    for passive_check in config.passive_exclude.iter() {
        if let Some(a) = checks.get_mut("passive") {
            a.remove(passive_check.as_str());
        }
    }
    for active_check in config.active_include.iter() {
         println!("hey");
        if let Some(a) = checks.get_mut("active") {
            println!("hereree");
            a.insert(active_check.as_str());
            dbg!(&a);
        }
        
    }
    for passive_check in config.passive_include.iter() {
        if let Some(a) = checks.get_mut("passive") {
            a.insert(passive_check.as_str());
        }
    }
    let mut report = json!({});
    dbg!(&checks);
    for check_type in checks.keys() {
        match check_type.to_owned() {
            "info" => {
                verbose_print(config, None, "Running info checks...");
                report["info"] = run_profile_info(config, &oas_json)?;
            },
            "passive" => {
                verbose_print(config, None, "Running passive checks...");
                report["passive"] = run_passive_profile(config, &oas, &oas_json, &checks[check_type])?;
            },
            "active" => {
                verbose_print(config, None, "Running active checks...");
                report["active"] = run_active_profile(config, &oas, &oas_json, &checks[check_type]).await?;
            },
            _ => {
                return Err(anyhow::anyhow!("Unknown check type: {}", check_type));
            }
        }
    }
    Ok(report)
}



fn run_profile_info(
    config: &Config,
    oas_json: &Value
) -> anyhow::Result<Value> {
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
    checks: &HashSet<&str>
) -> anyhow::Result<Value> {
    // Creating active scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating active scan struct...",
    );
    let checks : Vec<ActiveChecks> = checks
        .iter()
        .filter_map(|check| {
            ActiveChecks::from_string(check)
        })
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
        .run(active_scanner::ActiveScanType::Partial(checks), &temp_auth)
        .await;
    let active_result: HashMap<&str, Vec<Alert>> = active_scan
        .checks
        .iter()
        .map(|check| (check.name(), check.inner()))
        .collect();
    let report = json!({ "active": active_result });
    Ok(report)
}

fn run_passive_profile(
    config: &Config,
    oas: &OAS3_1,
    oas_json: &Value,
    checks: &HashSet<&str>,
) -> anyhow::Result<Value> {
    dbg!(&config.passive_exclude);
    // Creating passive scan struct
    verbose_print(
        config,
        Some(Verbosity::Debug),
        "Creating passive scan struct...",
    );
    let checks : Vec<PassiveChecks> = checks
        .iter()
        .filter_map(|check| {
            PassiveChecks::from_string(check)
        })
        .collect();

    let mut passive_scan = passive_scanner::PassiveSwaggerScan {
        swagger: oas.clone(),
        swagger_value: oas_json.clone(),
        passive_checks: vec![],
        verbosity: 0,
    };

    // Running passive scan
    verbose_print(config, None, "Running passive scan...");
    passive_scan.run(passive_scanner::PassiveScanType::Partial(checks));
    let passive_result: HashMap<&str, Vec<Alert>> = passive_scan
        .passive_checks
        .iter()
        .map(|check| (check.name(), check.inner()))
        .collect();
    Ok(json!({ "passive": passive_result }))

}
