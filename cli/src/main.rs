use attacker::{Authorization, Verbosity};
use swagger::{ActiveScanType,Authorization as SAuthorization};
use clap::{App, Arg, Error};
use colored::*;
use cherrybomb::*;
use mapper::digest::Header;

const VERSION: &str = "0.5.0";
const MAP_FILE: &str = "map";
const DECIDE_FILE: &str = "decide";
const SWAGGER_OUTPUT_FILE: &str = "results.txt";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let matches = App::new("CHERRYBOMB")
        .version(VERSION)
        .author("<support@blstsecurity.com>")
        .about("Blst cli app")
        .subcommand(App::new("add_token")
            .about("Creates a client token file with the given token")
            .arg(Arg::with_name("TOKEN")
                .short("t")
                .long("token")
                .value_name("Client Token Name")
                .help("The client token you got from firecracker's webpage")
                .required(true)
                .takes_value(true)))
        .subcommand(App::new("swagger")
            .about("Runs a set of passive checks on a given swagger file")
            .arg(Arg::with_name("FILE")
                .short("f")
                .long("file")
                .value_name("Swagger file")
                .help("The swagger file")
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("VERBOSITIY")
                .short("v")
                .long("verbosity")
                .value_name("Output verbosity")
                .help("The output's verbosity level, 0 - check table and alert table, 1 - full check table, 2 - only failed checks(table)")
                .takes_value(true)
                .default_value("1"))
            .arg(Arg::with_name("ACTIVE")
                .short("aaa")
                .long("active")
                .value_name("Active flag")
                .help("A flag to dictate whether or not an active scan will be preformed")
                .takes_value(false))
            .arg(Arg::with_name("PTABLE")
                .short("pt")
                .long("param-table")
                .value_name("Parameter table flag")
                .help("A flag to dictate whether or not it should print the parameter table")
                .takes_value(false))
            .arg(Arg::with_name("OUTPUT")
                .short("o")
                .long("output")
                .value_name("Output file")
                .help("The output file, for the alerts and checks")
                .takes_value(true)
                .default_value(SWAGGER_OUTPUT_FILE))
            .arg(Arg::with_name("SCAN")
                .short("s")
                .long("scan-type")
                .value_name("Scan type")
                .help("Sets the scan type - 0 - Full scan, 1 - Partial, 2 - Non-Invasive, 3 - Only tests")
                .takes_value(true)
                .default_value("0"))
            .subcommand(App::new("auth")                                   
                .about("Adds an auth token to the Attacker's requests, for auth based apps")
                .arg(Arg::with_name("TYPE")
                    //.short("tp")
                    .long("type")
                    .value_name("authorization type")
                    .help("Sets the authorization type, 0 - Basic, 1 - Bearer, 2 - JWT, 3 - API Key")
                    .required(true)
                    .takes_value(true))
                .arg(Arg::with_name("TOKEN")
                    //.short("tkn")
                    .long("token")
                    .value_name("authorization token value")
                    .help("Sets the authorization token(if it's of type basic then username:password)")
                    .required(true)
                    .takes_value(true))
            ))
        .subcommand(App::new("map")
            .about("Creates a new map from a given log file, outputs a digest file to the local directory")
            .arg(Arg::with_name("LOGS_FILE")
                .short("f")
                .long("file")
                .value_name("Logs File Name")
                .help("Indicate the file to set the map from")
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("OUTPUT")
                .short("o")
                .long("output")
                .value_name("Map File Name")
                .default_value("map")
                .help("Sets the output map file's name")
                .takes_value(true)))

        .subcommand(App::new("prepare")
            .about("Prepare the attacker for the attack")
            .arg(Arg::with_name("URL")
                .short("u")
                .long("url")
                .value_name("URL Address")
                .help("The attacked domain's URL")
                .required(true)
                .takes_value(true))
            .about("Prepare the attacker for the attack")
            .arg(Arg::with_name("MAP")
                .short("m")
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .help("The map file that the attack will be based on")
                .takes_value(true)))

        .subcommand(App::new("attack")
            .about("Attacks your domain based on an existing map")
            .arg(Arg::with_name("MAP")
                .short("m")
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .help("The map file that the attack will be based on")
                .takes_value(true))
            .arg(Arg::with_name("DECIDE_FILE")
                .short("o")
                .long("output")
                .value_name("Decide File Name")
                .default_value("decide")
                .help("Sets the output decide file's name")
                .takes_value(true))
            .arg(Arg::with_name("POP")
                .short("p")
                .long("population")
                .value_name("Population Number")
                .default_value("0")
                .help("Sets the population number")
                .takes_value(true))
            .arg(Arg::with_name("GEN")
                .short("g")
                .long("generations")
                .value_name("Generations Number")
                .default_value("1")
                .help("Sets the max generations number")
                .takes_value(true))
            .arg(Arg::with_name("HEADER")
                .short("h")
                .long("header")
                .value_name("header")
                .help("Adds the header to the default request headers of the attacker")
                .takes_value(true))
            .arg(Arg::with_name("VERBOSITY")
                .short("v")
                .long("verbosity")
                .value_name("Verboseity level")
                .default_value("1")
                .help("Sets the level of verbosity, 0 - Max, 1 - Default, 2 - Basic, 3 - None")
                .takes_value(true))
            .subcommand(App::new("auth")                                   
                .about("Adds an auth token to the Attacker's requests, for auth based apps")
                .arg(Arg::with_name("TYPE")
                    //.short("t")
                    .long("type")
                    .value_name("authorization type")
                    .help("Sets the authorization type, 0 - Basic, 1 - Bearer, 2 - JWT, 3 - API Key")
                    .required(true)
                    .takes_value(true))
                .arg(Arg::with_name("TOKEN")
                    //.short("tkn")
                    .long("token")
                    .value_name("authorization token value")
                    .help("Sets the authorization token(if it's of type basic then username:password)")
                    .required(true)
                    .takes_value(true))
                ))
        .subcommand(App::new("decide")
            .about("Decide whether or not a log file contains anomalies")
            .arg(Arg::with_name("LOG_FILE")
                .short("f")
                .long("file")
                .value_name("Log File Name")
                .help("Sets the source logs file")
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("MAP")
                .short("m")
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .help("Sets the source map file")
                .takes_value(true)))

        .subcommand(App::new("load")
            .about("Load logs to an existing map")
            .arg(Arg::with_name("LOGS_FILE")
                .short("f")
                .long("file")
                .value_name("Logs File Name")
                .help("Sets the source logs file")
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("MAP")
                .short("m")
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .help("Sets the map file that you want to update")
                .takes_value(true)))
        .get_matches();

    if let Some(vars) = matches.subcommand_matches("add_token") {
        if let Some(t) = vars.value_of("TOKEN") {
            add_token(t.to_string());
        }
    } else if let Some(vars) = matches.subcommand_matches("swagger"){
        if let Some(file) = vars.value_of("FILE"){
            let output = if let Some(o) = vars.value_of("OUTPUT"){ o } else { SWAGGER_OUTPUT_FILE };
            let verbosity = if let Some(v) = vars.value_of("VERBOSITY"){ v.parse::<u8>().unwrap() } else { 1 } ;
            let active = vars.is_present("ACTIVE");
            let param_table = vars.is_present("PTABLE");
            let scan_type = match vars.value_of("SCAN") {
                Some(r) => {
                    match r {
                        "0" => ActiveScanType::Full,
                        "1" => ActiveScanType::Partial(vec![]),
                        "2" => ActiveScanType::NonInvasive,
                        "3" => ActiveScanType::OnlyTests,
                        _   => ActiveScanType::Partial(vec![]),
                    }
                },
                None => ActiveScanType::Partial(vec![]),
            };
            let a = match vars.subcommand_matches("auth") {
                Some(vars) => match vars.value_of("TYPE") {
                    Some(v) => match vars.value_of("TOKEN") {
                        Some(v2) => SAuthorization::from_parts(v, v2.to_string()),
                        None => SAuthorization::None,
                    },
                    None => SAuthorization::None,
                },
                None => SAuthorization::None,
            };
            run_swagger(file,verbosity,output,&a,active,param_table,scan_type);
        }
    }else if let Some(vars) = matches.subcommand_matches("map") {
        if let Some(l) = vars.value_of("LOGS_FILE") {
            if let Some(o) = vars.value_of("OUTPUT") {
                map(l.to_string(), o.to_string());
            } else {
                map(l.to_string(), MAP_FILE.to_string());
            }
        }
    } else if let Some(vars) = matches.subcommand_matches("prepare") {
        if let Some(u) = vars.value_of("URL") {
            if let Some(m) = vars.value_of("MAP") {
                prepare_attacker(u.to_string(), m.to_string());
            } else {
                prepare_attacker(u.to_string(), MAP_FILE.to_string());
            }
        }
    } else if let Some(vars) = matches.subcommand_matches("attack") {
        let m = match vars.value_of("MAP") {
            Some(r) => r.to_string(),
            None => MAP_FILE.to_string(),
        };
        let o = match vars.value_of("DECIDE_FILE") {
            Some(r) => r.to_string(),
            None => DECIDE_FILE.to_string(),
        };
        let p = match vars.value_of("POP") {
            Some(r) => r.parse::<usize>().unwrap(),
            None => 0usize,
        };
        let g = match vars.value_of("GEN") {
            Some(r) => r.parse::<usize>().unwrap(),
            None => 1usize,
        };
        let v = match vars.value_of("VERBOSITY") {
            Some(r) => match r {
                "0" => {
                    println!("Verbosity level is Max");
                    Verbosity::Verbose
                }
                "1" => {
                    println!("Verbosity level is Default");
                    Verbosity::Default
                }
                "2" => {
                    println!("Verbosity level is Basic");
                    Verbosity::Basic
                }
                "3" => {
                    println!("Verbosity level is None");
                    Verbosity::None
                }
                _ => {
                    println!("Verbosity level is Default");
                    Verbosity::Default
                }
            },
            None => Verbosity::Default,
        };
        let h = match vars.value_of("HEADER") {
            Some(h) => {
                if !h.trim().is_empty() {
                    let split1 = h.split(':').collect::<Vec<&str>>();
                    vec![Header::from(split1[0], split1[1])]
                } else {
                    vec![]
                }
            }
            None => vec![],
        };
        let a = match vars.subcommand_matches("auth") {
            Some(vars) => match vars.value_of("TYPE") {
                Some(v) => match vars.value_of("TOKEN") {
                    Some(v2) => Authorization::from_parts(v, v2.to_string()),
                    None => Authorization::None,
                },
                None => Authorization::None,
            },
            None => Authorization::None,
        };
        attack_domain(m, o, p, g, v, h, a).await;
    } else if let Some(vars) = matches.subcommand_matches("decide") {
        if let Some(d) = vars.value_of("LOG_FILE") {
            if let Some(m) = vars.value_of("MAP") {
                decide_sessions(d.to_string(), m.to_string());
            } else {
                decide_sessions(d.to_string(), MAP_FILE.to_string());
            }
        }
    } else if let Some(vars) = matches.subcommand_matches("load") {
        if let Some(l) = vars.value_of("LOGS_FILE") {
            if let Some(m) = vars.value_of("MAP") {
                load(l.to_string(), m.to_string());
            } else {
                load(l.to_string(), MAP_FILE.to_string());
            }
        }
    } else {
        //println!("\n\n\n######  #        #####  #######\n#     # #       #     #    #\n#     # #       #          #\n######  #        #####     #\n#     # #             #    #\n#     # #       #     #    #\n######  #######  #####     #\n\n");
        println!(
            "\n\n\n  __ ._______   .____      ._______________________.  __
 / /\\/      /\\  /   /\\     /   _______             /\\/ /\\
/_/ /    ----/\\/   /_/__  /_____     /___.    ____/ /_/ /
\\ \\/    __  / /        /\\/   /_/    / / /     /\\__\\/\\_\\/
  /________/ /________/ /__________/ / /_____/ /
  \\.   .___\\/\\.   .___\\/\\.   ._____\\/  \\. .__\\/\n\n"
        );
        println!("\nFIRECRACKER v{}", VERSION);
        println!("\nFor more information try {}", "--help".green());
    }
    Ok(())
}
