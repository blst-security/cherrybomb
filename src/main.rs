mod error;
mod options;
mod table;
mod telemetry;

use cherrybomb_engine::config::Config;
use clap::Parser;
use std::fs::File;
use std::process::ExitCode;

use crate::options::Options;
use crate::table::print_tables;

fn open_config_file(config_location: &std::path::PathBuf) -> anyhow::Result<Config> {
    return match config_location.extension() {
        Some(ext) => {
            let file = match File::open(config_location) {
                Ok(file) => file,
                Err(e) => Err(anyhow::anyhow!("Error opening config file: {}", e))?,
            };
            match ext.to_str() {
                Some("json") => {
                    let config: Config = match serde_json::from_reader(file) {
                        Ok(config) => config,
                        Err(e) => Err(anyhow::anyhow!("Error parsing config file: {}", e))?,
                    };
                    Ok(config)
                }
                Some("yaml") => {
                    let config: Config = match serde_yaml::from_reader(file) {
                        Ok(config) => config,
                        Err(e) => Err(anyhow::anyhow!("Error parsing config file: {}", e))?,
                    };
                    Ok(config)
                }
                _ => Err(anyhow::anyhow!("Unsupported config file extension")),
            }
        }
        _ => Err(anyhow::anyhow!("Unsupported config file extension")),
    };
}

fn merge_options(conf: &mut Config, opt: &Options) {
    if let Some(value) = &opt.profile {
        conf.profile = value.clone();
    }
    if let Some(value) = &opt.verbosity {
        conf.verbosity = value.clone();
    }
    if let Some(value) = &opt.file {
        conf.file = value.clone();
    }
    if let Some(options::Commands::Auth(value)) = &opt.command {
        conf.security.push(value.clone());
    }
    if let Some(value) = &opt.ignore_tls_errors {
        conf.ignore_tls_errors = *value;
    }
    if let Some(server_item) = &opt.server {
        conf.servers_override = vec![server_item.clone()];
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    println!("{}", options::BANNER);
    let opt = options::Options::parse();
    let mut config = if let Some(config_location) = &opt.config {
        open_config_file(config_location)?
    } else {
        Config::default()
    };
    merge_options(&mut config, &opt);
    if !opt.no_telemetry {
        telemetry::send(config.profile.clone(), config.verbosity.clone()).await.unwrap_or_default();
    }
    let json_val = cherrybomb_engine::run(&mut config).await?;
    match print_tables(json_val, &opt) {
        Ok(exit_code) => Ok(exit_code),
        Err(e) => Err(anyhow::anyhow!("Error printing tables: {}", e)),
    }
}
