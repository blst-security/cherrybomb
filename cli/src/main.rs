use clap::{Parser,Subcommand,ArgAction};
use swagger::ActiveChecks;
use swagger::PassiveChecks;
use std::str::FromStr;
use std::fmt;
use colored::*;
use cli::*;



const SWAGGER_OUTPUT_FILE: &str = "results.txt";

#[derive(Copy,Clone,Debug)]
pub enum OutputFormat{
    Json,
    Txt,
    Cli,
    Web
}
impl FromStr for OutputFormat {
    type Err = &'static str;
    fn from_str(input: &str) -> Result<OutputFormat, Self::Err> {
        match input.to_lowercase().as_str() {
            "json"  => Ok(OutputFormat::Json),
            "txt"  => Ok(OutputFormat::Txt),
            "cli"  => Ok(OutputFormat::Cli),
            "web"  => Ok(OutputFormat::Web),
            _      => Err("None"),
        }
    }
}
impl fmt::Display for OutputFormat{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self{
            Self::Json=>write!(f, "JSON"),
            Self::Txt=>write!(f, "TXT"),
            Self::Cli=>write!(f, "CLI"),
            Self::Web=>write!(f, "WEB"),
        }
    }
}

#[derive(Parser,Debug,Clone)]
#[clap(name = "auth")]
pub struct AuthOpt {
    ///Sets the authorization type, 0 - Basic, 1 - Bearer, 2 - JWT, 3 - API Key, 4 - Cookie, 5 - Custom
    #[clap(short,long="type")]
    tp:String,
    ///Sets the authorization token
    ///If it's of type basic then username:password
    ///If it's Custom then the scheme is delivery method,name,value->headers,X-CUSTOM-HEADER,value
    ///For all other option, just the token
    #[clap(long)]
    token:String,
}

#[derive(Subcommand,Debug,Clone)]
pub enum AuthCmd{
    ///Adds an auth token to the Attacker's requests, for auth based apps
    Auth(AuthOpt),
}
#[derive(Parser, Debug,Clone)]
#[clap(name = "oas")]
pub struct OASOpt {
    ///The output's verbosity level, 0 - check table and alert table, 1 - full check table, 2 - only failed checks(table)
    #[clap(short = 'v', long)]
    verbosity: Option<u8>,
    ///The output's format type -> cli/txt/json
    #[clap(long,default_value_t=OutputFormat::Cli)]
    format: OutputFormat,
    ///The output file, for the alerts and checks
    #[clap(short, long)]
    output: Option<String>,
    ///The OAS file path
    #[clap(long,short)]
    file: String,
    ///The Passive Scan Type to run, 0 - Full, 1 - Partial (list of checks)
    #[clap(short,long)]
    passive_scan_type: Option<i32>, 
    ///Use passive_scan_checks as an exclude list, if the passive scan type is partial (1 - true, 0 - false)
    #[clap(long)]
    exclude_passive_checks: Option<i8>,
    ///The list of checks to run/exclude, if the passive_scan_type is 1
    /// ex: "check1,check2,check3"
    #[clap(long,required_if("passive-scan-type", "1"), requires("exclude-passive-checks"))]
    passive_scan_checks: Option<Vec<String>>,
    #[clap(long,takes_value = false,action = ArgAction::SetTrue)]
    no_active: bool,
    ///The Active Scan Type to run, 0 - Full, 1 - Non invasive, 2 - only tests, 3 - Partial (list of checks)
    #[clap(short,long)]
    active_scan_type: Option<i32>,
    ///The list of checks to run, if the active_scan_type is 3
    /// ex: "check1,check2,check3"
    #[clap(long,required_if("active-scan-type", "3"), requires("exclude-active-checks"))]
    active_scan_checks: Option<Vec<String>>,
    ///Use active_scan_checks as an exclude list, if the active scan type is partial (1 - true, 0 - false)
    #[clap(long)]
    exclude_active_checks: Option<i8>,
    #[clap(long)]
    no_telemetry: Option<bool>,
    #[clap(subcommand)]
    auth:Option<AuthCmd>,
}
#[derive(Parser, Debug,Clone)]
#[clap(name = "param-table")]
pub struct ParamTableOpt {
    ///An option to present a single parameter with that name.
    #[clap(short, long)]
    name:Option<String>,
    ///The output file
    #[clap(short, long)]
    output: Option<String>,
    ///The OAS file
    #[clap(long,short)]
    file: String,
    #[clap(long)]
    no_telemetry: Option<bool>,
}
#[derive(Parser, Debug,Clone)]
#[clap(name = "ep-table")]
pub struct EpTableOpt {
    ///An option to present a single endpoint with that path
    #[clap(short, long)]
    path:Option<String>,
    ///The output file
    #[clap(short, long)]
    output: Option<String>,
    ///The OAS file
    #[clap(long,short)]
    file: String,
    #[clap(long)]
    no_telemetry: Option<bool>,
}

#[derive(Subcommand,Debug,Clone)]
enum Commands{
    ///Runs a set of passive checks on a given OpenAPI specification file
    Oas(OASOpt),
    ///Prints out a param table given an OpenAPI specification file
    ParamTable(ParamTableOpt),
    ///Prints out an endpoint table given an OpenAPI specification file
    EpTable(EpTableOpt),
}
#[derive(Parser,Debug,Clone)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

pub async fn parse_oas(oas:OASOpt){
    println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
    if oas.no_active{
        try_send_telemetry(oas.no_telemetry,"passive oas scan").await;
    }else{
        try_send_telemetry(oas.no_telemetry,"passive and active oas scan").await;
    }
    if let OutputFormat::Web = oas.format{
        std::process::exit(0);
    }
    let res = run_swagger(
        &oas.file,
        oas.verbosity.unwrap_or(1),
        Some(oas.output.unwrap_or_else(||SWAGGER_OUTPUT_FILE.to_string())),
        match oas.auth{
                Some(AuthCmd::Auth(auth))=>{
                    swagger::Authorization::from_parts(&auth.tp, auth.token)
                },
                _ => swagger::Authorization::None
            },
            match oas.active_scan_type{
                Some(0)=>swagger::ActiveScanType::Full,
                Some(1)=>swagger::ActiveScanType::NonInvasive,
                Some(2)=>swagger::ActiveScanType::OnlyTests,
                Some(3)=>swagger::ActiveScanType::Partial(
                    ActiveChecks::parse_check_list(
                        oas.active_scan_checks.unwrap_or_default(),
                        oas.exclude_active_checks.unwrap_or(0) == 1)
                ),
                _=>swagger::ActiveScanType::Full,
            },
            match oas.passive_scan_type{
                Some(0)=>swagger::PassiveScanType::Full,
                Some(1)=>swagger::PassiveScanType::Partial(
                    PassiveChecks::parse_check_list(
                        oas.passive_scan_checks.unwrap_or_default(),
                        oas.exclude_passive_checks.unwrap_or(0) == 1)
                ),
                _=>swagger::PassiveScanType::Full,
            },
            matches!(oas.format, OutputFormat::Json)
           
    ).await;
    std::process::exit(res.into());
}

pub async fn parse_param_table(p_table:ParamTableOpt){
    try_send_telemetry(p_table.no_telemetry,"param_table").await;
    param_table(&p_table.file,p_table.name); 
    println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
}
pub async fn parse_ep_table(e_table:EpTableOpt){
    try_send_telemetry(e_table.no_telemetry,"ep_table").await;
    ep_table(&e_table.file,e_table.path);
    println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
}


#[tokio::main]
async fn main() {
    let opt = Cli::parse();
    match opt.command{
        Commands::Oas(opt)=>parse_oas(opt).await,
        Commands::ParamTable(opt)=>parse_param_table(opt).await,
        Commands::EpTable(opt)=>parse_ep_table(opt).await,
    }
}

