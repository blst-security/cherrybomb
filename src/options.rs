use cherrybomb_engine::config::*;
use clap::{Parser, Subcommand, ValueEnum};
use const_format::formatcp;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Options {
    #[arg(short, long, value_enum)]
    /// Level of verbosity
    pub verbosity: Option<Verbosity>,

    #[arg(short, long, required_unless_present = "config")]
    /// Input OAS file (required unless input file is specified in config)
    pub file: Option<std::path::PathBuf>,

    #[arg(short, long, default_value = None)]
    /// Output file
    pub output: Option<std::path::PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    /// Output format
    pub format: OutputFormat,

    #[arg(short, long, default_value_t = false)]
    /// Disable console output (output is lost if no output file is specified)
    pub quiet: bool,

    #[arg(short, long, default_value = None, required_unless_present = "file")]
    /// Config file to use (required if no input file)
    pub config: Option<std::path::PathBuf>,

    #[arg(short, long, value_enum)]
    /// Profile to use
    pub profile: Option<Profile>,

    #[command(subcommand)]
    /// Authentication definition
    pub command: Option<Commands>,

    #[arg(long)]
    /// Override OAS servers with this server
    pub server: Option<String>,

    #[arg(short, long, value_enum)]
    /// Ignore tls errors
    pub ignore_tls_errors: Option<bool>,

    #[arg(long, default_value_t = false)]
    pub no_telemetry: bool,

    #[arg(long, default_value_t = false)]
    /// Use this flag to disable color output
    pub no_color: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Authentication definition
    Auth(Auth),
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Json,
    Table,
    // Text,
}

pub const BANNER: &str = formatcp!(
    "
╭━━━┳╮╱╱╱╱╱╱╱╱╱╱╱╱╭╮╱╱╱╱╱╱╱╭╮
┃╭━╮┃┃╱╱╱╱╱╱╱╱╱╱╱╱┃┃╱╱╱╱╱╱╱┃┃
┃┃╱╰┫╰━┳━━┳━┳━┳╮╱╭┫╰━┳━━┳╮╭┫╰━╮
┃┃╱╭┫╭╮┃┃━┫╭┫╭┫┃╱┃┃╭╮┃╭╮┃╰╯┃╭╮┃
┃╰━╯┃┃┃┃┃━┫┃┃┃┃╰━╯┃╰╯┃╰╯┃┃┃┃╰╯┃
╰━━━┻╯╰┻━━┻╯╰╯╰━╮╭┻━━┻━━┻┻┻┻━━╯
╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃
╱╱╱╱╱╱╱╱╱╱╱╱╱╱╰━━╯       v{}
",
    env!("CARGO_PKG_VERSION")
);
