use clap::{Arg, App, Error};
use blst_cli_app::*;
use colored::*;

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
            .about("Create a new map file")
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
                .about("Sets the new map file output")
                .takes_value(true)))
        .subcommand(App::new("attack")
            .about("Attack domain")
            .version("1.0")
            .arg(Arg::new("DOMAIN")
                .short('d')
                .long("domain")
                .value_name("Domain Name")
                .about("Sets the attacked domain name")
                .required(true)
                .takes_value(true))
            .arg(Arg::new("MAP")
                .short('m')
                .long("map")
                .value_name("Map File Name")
                .about("Sets the map file that the atttack will be based on")
                .takes_value(true))
            .arg(Arg::new("DECIDE_FILE")
                .short('o')
                .long("output")
                .value_name("Decide File Name")
                .about("Sets the decide file that the atttack will be based on")
                .takes_value(true)))
        .subcommand(App::new("decide")
            .about("Decide")
            .version("1.0")
            .arg(Arg::new("DECIDE_FILE")
                .short('f')
                .long("file")
                .value_name("Logs File Name")
                .about("Sets the source logs file")
                .takes_value(true)))
            .subcommand(App::new("load")
                .about("Load logs file to an existing map")
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
                    .about("Update The Selected Map File")
                    .takes_value(true)))
        /*
        .arg(Arg::new("v")
            .short('v')
            .multiple_occurrences(true)
            .takes_value(true)
            .about("Sets the level of verbosity"))*/
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
            if let Some(m) = vars.value_of("MAP") {
                if let Some(o) = vars.value_of("DECIDE_FILE") {
                    attack(d.to_string(), m.to_string(), o.to_string());
                } else {
                    attack(d.to_string(), m.to_string(), DECIDE_FILE.to_string());
                }
            } else {
                if let Some(o) = vars.value_of("DECIDE_FILE") {
                    attack(d.to_string(), MAP_FILE.to_string(), o.to_string());
                } else {
                    attack(d.to_string(), MAP_FILE.to_string(), DECIDE_FILE.to_string());
                }
            }
        }
    }
    else if let Some(vars) = matches.subcommand_matches("decide") {
        if let Some(d) = vars.value_of("DECIDE_FILE") {
            decide(d.to_string());
        } else {
            decide(DECIDE_FILE.to_string());
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
        /*
        let a = executor::block_on(get_access("Map"));
        if a {
            println!("{}", a);
        }*/
        println!("\n\n\n######  #        #####  #######\n#     # #       #     #    #\n#     # #       #          #\n######  #        #####     #\n#     # #             #    #\n#     # #       #     #    #\n######  #######  #####     #\n\n");
        println!("\nFIRECRACKER v{}", VERSION.to_string());
        println!("\nFor more information try {}", "--help".green());
    }
    
    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences

    /*
    match matches.occurrences_of("v") {
        0 => println!("Verbose mode is off"),
        1 => println!("Verbose mode is kind of on"),
        2 => println!("Verbose mode is on"),
        _ => println!("Don't be crazy"),
    }
    */

    // Continued program logic goes here...
    Ok(())
}
