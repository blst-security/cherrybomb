use attacker::Verbosity;
use clap::{App, Arg, Error};
use colored::*;
use firecracker::*;

const VERSION: &str = "0.2.0";
const MAP_FILE: &str = "map";
const DECIDE_FILE: &str = "decide";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let matches = App::new("FIRECRACKER")
        .version(VERSION)
        .author("<support@blstsecurity.com>")
        .about("Blst cli app")
        .subcommand(App::new("add_token")
            .about("Creates a client token file with the given token")
            .arg(Arg::new("TOKEN")
                .short('t')
                .long("token")
                .value_name("Client Token Name")
                .about("The client token you got from firecracker's webpage")
                .required(true)
                .takes_value(true)))

        .subcommand(App::new("map")
            .about("Creates a new map from a given log file, outputs a digest file to the local directory")
            .arg(Arg::new("LOGS_FILE")
                .short('f')
                .long("file")
                .value_name("Logs File Name")
                .about("Indicate the file to set the map from")
                .required(true)
                .takes_value(true))
            .arg(Arg::new("OUTPUT")
                .short('o')
                .long("output")
                .value_name("Map File Name")
                .default_value("map")
                .about("Sets the output map file's name")
                .takes_value(true)))

        .subcommand(App::new("prepare")
            .about("Prepare the attacker for the attack")
            .arg(Arg::new("URL")
                .short('u')
                .long("url")
                .value_name("URL Address")
                .about("The attacked domain's URL")
                .required(true)
                .takes_value(true))
            .about("Prepare the attacker for the attack")
            .arg(Arg::new("MAP")
                .short('m')
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .about("The map file that the attack will be based on")
                .takes_value(true)))

        .subcommand(App::new("attack")
            .about("Attacks your domain based on an existing map")
            .arg(Arg::new("MAP")
                .short('m')
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .about("The map file that the attack will be based on")
                .takes_value(true))
            .arg(Arg::new("DECIDE_FILE")
                .short('o')
                .long("output")
                .value_name("Decide File Name")
                .default_value("decide")
                .about("Sets the output decide file's name")
                .takes_value(true))
            .arg(Arg::new("POP")
                .short('p')
                .long("population")
                .value_name("Population Number")
                .default_value("0")
                .about("Sets the population number")
                .takes_value(true))
            .arg(Arg::new("GEN")
                .short('g')
                .long("generations")
                .value_name("Generations Number")
                .default_value("1")
                .about("Sets the max generations number")
                .takes_value(true))
            .arg(Arg::new("VERBOSITY")
                .short('v')
                .long("verbosity")
                .value_name("Verboseity level")
                .default_value("1")
                .about("Sets the level of verbosity, 0 - Max, 1 - Default, 2 - Basic, 3 - None")
                .takes_value(true)))

        .subcommand(App::new("decide")
            .about("Decide whether or not a log file contains anomalies")
            .arg(Arg::new("LOG_FILE")
                .short('f')
                .long("file")
                .value_name("Log File Name")
                .about("Sets the source logs file")
                .required(true)
                .takes_value(true))
            .arg(Arg::new("MAP")
                .short('m')
                .long("map")
                .value_name("Map File Name")
                .default_value("map")
                .about("Sets the source map file")
                .takes_value(true)))

        .subcommand(App::new("load")
            .about("Load logs to an existing map")
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
                .default_value("map")
                .about("Sets the map file that you want to update")
                .takes_value(true)))
        .get_matches();

    if let Some(vars) = matches.subcommand_matches("add_token") {
        if let Some(t) = vars.value_of("TOKEN") {
            add_token(t.to_string());
        }
    } else if let Some(vars) = matches.subcommand_matches("map") {
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
        attack_domain(m, o, p, g, v).await;
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
