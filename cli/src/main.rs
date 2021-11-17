use clap::{Arg, App, Error};
use firecracker::*;
use colored::*;
use attacker::Verbosity;

const VERSION:&'static str = "1.0.0";
const MAP_FILE:&'static str = "map";
const DECIDE_FILE:&'static str = "decide";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let matches = App::new("BLST CLI APP")
        .version("1.0")
        .author("Roy B. <roy.barnea@blstsecurity.com>")
        .about("Blst cli app")
        .subcommand(App::new("map")
            .about("Create a new map from log file")
            .version("1.0")
            .arg(Arg::new("LOGS_FILE")
                .short('f')
                .long("file")
                .value_name("Logs File Name")
                .about("Sets the source logs file")
                .required(true)
                .takes_value(true))
            .arg(Arg::new("OUTPUT")
                .short('o')
                .long("output")
                .value_name("Map File Name")
                .about("Sets the output map file")
                .takes_value(true)))

        .subcommand(App::new("attack")
            .about("Attack your domain based on an existing map")
            .version("1.0")
            .arg(Arg::new("DOMAIN")
                .short('d')
                .long("domain")
                .value_name("Domain Name")
                .about("The attacked domain name")
                .required(true)
                .takes_value(true))
            .arg(Arg::new("MAP")
                .short('m')
                .long("map")
                .value_name("Map File Name")
                .about("The map file that the attack will be based on")
                .takes_value(true))
            .arg(Arg::new("DECIDE_FILE")
                .short('o')
                .long("output")
                .value_name("Decide File Name")
                .about("Sets the output decide file")
                .takes_value(true))
            .arg(Arg::new("POP")
                .short('p')
                .long("population")
                .value_name("Population Number")
                .about("Sets the population number")
                .takes_value(true))
            .arg(Arg::new("GEN")
                .short('g')
                .long("generations")
                .value_name("Generations Number")
                .about("Sets the generations number")
                .takes_value(true))
            .arg(Arg::new("VERBOSITY")
                .short('v')
                .long("verbosity")
                .value_name("Verboseity level")
                .about("Sets the level of verbosity")
                .takes_value(true)))

        .subcommand(App::new("decide")
            .about("Decide")
            .version("1.0")
            .arg(Arg::new("DECIDE_FILE")
                .short('f')
                .long("file")
                .value_name("Decide File Name")
                .about("Sets the source decide file")
                .takes_value(true)))

        .subcommand(App::new("load")
            .about("Load logs to an existing map")
            .version("1.0")
            .arg(Arg::new("LOGS_FILE")
                .short('f')
                .long("file")
                .value_name("Logs File Name")
                .about("Sets the source logs file")
                .required(true)
                .takes_value(true))
            .arg(Arg::new("MAP")
                .short('m')
                .long("map")
                .value_name("Map File Name")
                .about("Sets the map file that you want to update")
                .takes_value(true)))
        .get_matches();

    if let Some(vars) = matches.subcommand_matches("map") {
        if let Some(l) = vars.value_of("LOGS_FILE") {
            if let Some(o) = vars.value_of("OUTPUT") {
                map(l.to_string(), o.to_string());
            } else {
                map(l.to_string(), MAP_FILE.to_string()); 
            }
        }
    }
    else if let Some(vars) = matches.subcommand_matches("attack") {
        if let Some(d) = vars.value_of("DOMAIN") {
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
                None => 3usize,
            };
            let v = match vars.value_of("VERBOSITY") {
                Some(r) => {
                    match r {
                        "0" => {
                            println!("Verbosity level is max");
                            Verbosity::Verbose
                        },
                        "1" => {
                            println!("Verbosity level is almost max");
                            Verbosity::Default
                        },
                        "2" => {
                            println!("Verbosity level is max");
                            Verbosity::Basic
                        },
                        "3" => {
                            println!("Verbosity level is max");
                            Verbosity::None
                        },
                        _ => {
                            println!("Verbosity level is max");
                            Verbosity::Default
                        },
                    }
                },
                None => Verbosity::Default,
            };
            attack_domain(d.to_string(),m, o, p, g, v).await;
        }
    }
    else if let Some(vars) = matches.subcommand_matches("decide") {
        if let Some(d) = vars.value_of("DECIDE_FILE") {
            decide_sessions(d.to_string());
        } else {
            decide_sessions(DECIDE_FILE.to_string());
        }
    }
    else if let Some(vars) = matches.subcommand_matches("load") {
        if let Some(l) = vars.value_of("LOGS_FILE") {
            if let Some(m) = vars.value_of("MAP") {
                load(l.to_string(), m.to_string());
            } else {
                load(l.to_string(), MAP_FILE.to_string());
            }
        }
    }
    else {
        //println!("\n\n\n######  #        #####  #######\n#     # #       #     #    #\n#     # #       #          #\n######  #        #####     #\n#     # #             #    #\n#     # #       #     #    #\n######  #######  #####     #\n\n");
        println!("\n\n\n  __ ._______   .____      ._______________________.  __
 / /\\/      /\\  /   /\\     /   _______             /\\/ /\\
/_/ /    ----/\\/   /_/__  /_____     /___.    ____/ /_/ /
\\ \\/    __  / /        /\\/   /_/    / / /     /\\__\\/\\_\\/
  /________/ /________/ /__________/ / /_____/ /
  \\.   .___\\/\\.   .___\\/\\.   ._____\\/  \\. .__\\/\n\n");
        println!("\nFIRECRACKER v{}", VERSION.to_string());
        println!("\nFor more information try {}", "--help".green());
    }
    Ok(())
}
