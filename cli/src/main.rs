use clap::{Parser,Subcommand};
use std::str::FromStr;
use std::fmt;
use colored::*;
use cli::*;
//use attacker::{Authorization, Verbosity};
//use mapper::digest::Header;
//use futures::executor::block_on;

//const MAP_FILE: &str = "map";
const SWAGGER_OUTPUT_FILE: &str = "results.txt";
const CONFIG_DEFAULT_FILE: &str = ".cherrybomb/config.json";
//const DECIDE_FILE: &str = "decide";

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
    ///The config file path
    #[clap(short,long)]
    config: Option<String>,
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
}
/*
#[derive(Parser, Debug,Clone)]
#[clap(name = "mapper")]
pub struct MapperOpt {
    ///The output map's file name
    #[clap(short, long)]
    output: Option<String>,
    ///The input log's file name
    #[clap(long,short)]
    file: String,
    ///OpenAPI specification given as a hint to the mapper
    #[clap(long,short)]
    lhint: Option<String>
}
#[derive(Parser, Debug,Clone)]
#[clap(name = "mapper")]
pub struct LoadOpt {
    ///The map the logs get loaded to
    #[clap(long,short)]
    map:Option<String>,
    ///The input's log file name
    #[clap(long,short)]
    file: String,
}
#[derive(Parser, Debug,Clone)]
#[clap(name = "prepare")]
pub struct PrepareOpt {
    ///The map file that serves as the attacker's scope
    #[clap(long,short,default_value_t=MAP_FILE.to_string())]
    map:String,
    ///The url to attack
    #[clap(long,short)]
    url: String,
}
#[derive(Parser,Debug,Clone)]
#[clap(name = "auth")]
pub struct AuthOpt {
    ///Sets the authorization type, 0 - Basic, 1 - Bearer, 2 - JWT, 3 - API Key
    #[clap(short,long="type")]
    tp:String,
    ///Sets the authorization token(if it's of type basic then username:password)
    #[clap(long)]
    token:String,
}
#[derive(Subcommand,Debug,Clone)]
pub enum AuthCmd{
    Auth(AuthOpt),
}
#[derive(Parser, Debug,Clone)]
#[clap(name = "attack")]
pub struct AttackOpt {
    ///The map file that the attack will be based on
    #[clap(long,short,default_value_t=MAP_FILE.to_string())]
    map:String,
    ///Sets the output decide file's name
    #[clap(long,short,default_value_t=DECIDE_FILE.to_string())]
    decide_file:String,
    ///Sets the population number
    #[clap(long,short,default_value_t=0)]
    population:u8,
    ///Sets the max generations number
    #[clap(long,short,default_value_t=1)]
    generations:u8,
    ///Adds the header to the default request headers of the attacker
    #[clap(long,short)]
    header:Option<String>,
    ///Sets the level of verbosity, 0 - Max, 1 - Default, 2 - Basic, 3 - None
    #[clap(long,short,default_value_t=1)]
    verbosity:u8,
    ///Adds an auth token to the Attacker's requests, for auth based apps
    #[clap(subcommand)]
    auth:Option<AuthCmd>,
}*/
#[derive(Subcommand,Debug,Clone)]
enum Commands{
    ///Runs a set of passive checks on a given OpenAPI specification file
    Oas(OASOpt),
    ///Runs a set of passive checks on a given OpenAPI specification file
    Swagger(OASOpt),
    ///Prints out a param table given an OpenAPI specification file
    ParamTable(ParamTableOpt),
    ///Prints out an endpoint table given an OpenAPI specification file
    EpTable(EpTableOpt),
    /*
    ///Creates a new map from a given log file, outputs a digest file to the local directory
    Mapper(MapperOpt),
    ///Load more logs to an existing map
    Load(LoadOpt),
    ///Prepare the attacker for the attack
    Prepare(PrepareOpt),
    ///Attacks your domain based on an existing map
    Attack(AttackOpt),*/
}
#[derive(Parser,Debug,Clone)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}
pub fn parse_oas(oas:OASOpt){
    let res = match oas.format{
        OutputFormat::Cli=>{
            let f = run_swagger(&oas.file,oas.verbosity.unwrap_or(1),oas.output,&oas.config.unwrap_or_else(|| {println!("No config file was loaded to the scan, default configuration is being used\n"); CONFIG_DEFAULT_FILE.to_string()}),false);
            println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
            f 
        },
        OutputFormat::Web=>{
            0
        },
        OutputFormat::Txt=>{
            let f = run_swagger(&oas.file,oas.verbosity.unwrap_or(1),
            Some(oas.output.unwrap_or_else(|| SWAGGER_OUTPUT_FILE.to_string())),
            &oas.config.unwrap_or_else(|| {println!("No config file was loaded to the scan, default configuration is being used\n"); CONFIG_DEFAULT_FILE.to_string()}),
            false
            );
            println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
            f 
        },
        OutputFormat::Json=>{
            run_swagger(&oas.file,oas.verbosity.unwrap_or(1),oas.output,&oas.config.unwrap_or_else(|| {println!("No config file was loaded to the scan, default configuration is being used\n"); CONFIG_DEFAULT_FILE.to_string()}),true)
        },
    };
    std::process::exit(res.into());
}
pub fn parse_param_table(p_table:ParamTableOpt){
    param_table(&p_table.file,p_table.name); 
    println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
}
pub fn parse_ep_table(e_table:EpTableOpt){
    ep_table(&e_table.file,e_table.path);
    println!("\n\nFor a WebUI version of the scan you can go to {} and run the OAS scan on the main page!\n","https://www.blstsecurity.com".bold().underline());
}
/*
pub fn parse_mapper(mapper:MapperOpt){
    map(mapper.file,mapper.output.unwrap_or_else(|| MAP_FILE.to_string()),mapper.lhint);
    println!("\n\nFor better map visualization you can go and sign up at {} and get access to our dashboards!\n","https://www.blstsecurity.com".bold().underline());
}
pub fn parse_load(load1:LoadOpt){
    load(load1.file,load1.map.unwrap_or_else(|| MAP_FILE.to_string()));
    println!("\n\nFor better map visualization you can go and sign up at {} and get access to our dashboards!\n","https://www.blstsecurity.com".bold().underline());
}
pub fn parse_prepare(prep:PrepareOpt){
    prepare_attacker(prep.url,prep.map);
}
pub fn parse_attack(attack:AttackOpt){
    let verbosity = match attack.verbosity{
        0 => {
            println!("Verbosity level is Max");
            Verbosity::Verbose
        }
        1 => {
            println!("Verbosity level is Default");
            Verbosity::Default
        }
        2 => {
            println!("Verbosity level is Basic");
            Verbosity::Basic
        }
        3 => {
            println!("Verbosity level is None");
            Verbosity::None
        }
        _ => {
            println!("Verbosity level is Default");
            Verbosity::Default
        }
    };
    let auth = if let Some(AuthCmd::Auth(opt)) = attack.auth{
        Authorization::from_parts(&opt.tp,opt.token) 
    }else{
        Authorization::None
    };
    let header = match attack.header{
        Some(h)=>{
            if !h.trim().is_empty() {
                let split1 = h.split(':').collect::<Vec<&str>>();
                vec![Header::from(split1[0], split1[1])]
            } else {
                vec![]
            }
        },
        None=>vec![],
    };
    block_on(attack_domain(attack.map,attack.decide_file,attack.population.into(),attack.generations.into(),verbosity,header,auth));
}*/
fn main() {
    let opt = Cli::parse();
    match opt.command{
        Commands::Oas(opt)=>parse_oas(opt),
        Commands::Swagger(opt)=>parse_oas(opt),
        Commands::ParamTable(opt)=>parse_param_table(opt),
        Commands::EpTable(opt)=>parse_ep_table(opt),
        /*Commands::Mapper(opt)=>parse_mapper(opt),
        Commands::Load(opt)=>parse_load(opt),
        Commands::Prepare(opt)=>parse_prepare(opt),
        Commands::Attack(opt)=>parse_attack(opt),*/
/*        _=>{
            println!(
            "\n\n\n  __ ._______   .____      ._______________________.  __
 / /\\/      /\\  /   /\\     /   _______             /\\/ /\\
/_/ /    ----/\\/   /_/__  /_____     /___.    ____/ /_/ /
\\ \\/    __  / /        /\\/   /_/    / / /     /\\__\\/\\_\\/
  /________/ /________/ /__________/ / /_____/ /
  \\.   .___\\/\\.   .___\\/\\.   ._____\\/  \\. .__\\/\n"
            );
            println!("\nCHERRYBOMB v{}", VERSION);
            println!("\nFor more information try {}", "--help".green());
        }*/
    }
}

