use super::*;
use attacker::*;
use colored::*;
use decider::*;
use mapper::digest::*;
use mapper::*;
use url::Url;
use swagger::scan::passive::PassiveSwaggerScan;
use swagger::scan::Level;
//use swagger::scan::active::{ActiveScan,ActiveScanType};
use swagger::{Swagger,OAS3_1,OAS,Check/*,Authorization as SAuth*/,ParamTable,EpTable};
//use futures::executor;
/*
pub fn add_token(token: String) -> bool {
    match Uuid::parse_str(&token) {
        Ok(_) => {
            match OpenOptions::new()
                .write(true)
                .create(true)
                .open(format!("{}.txt", "token"))
            {
                Ok(mut r) => match r.write_all(token.as_bytes()) {
                    Ok(_) => true,
                    Err(_) => {
                        print_err("Failed writing token to file");
                        false
                    }
                },
                Err(_) => {
                    print_err("Failed to create token file");
                    false
                }
            }
        }
        Err(e) => {
            print_err(&format!("Invalid token, {:?}", e));
            false
        }
    }
}
*/
pub fn run_passive_swagger_scan<T>(scan_try:Result<PassiveSwaggerScan<T>,&'static str>,verbosity:u8,output_file:Option<String>,conf:Config,json:bool) -> i8
where T:OAS+Serialize+for<'de> Deserialize<'de>{
    let mut scan = match scan_try{
        Ok(s)=>s,
        Err(e)=>{
            print_err(e);
            return -1;
        },
    };
    scan.run(conf.scan_type);
    let failed = if json{
        println!("{}",serde_json::to_string(&scan).unwrap());
        scan.passive_checks.iter().map(|c| if (conf.fail_on_info && c.result()=="FAILED") || (c.top_severity() >Level::Info) { 1 } else { 0 }).sum()
    } else{
        scan.print(verbosity);
        scan.passive_checks.iter().map(|c| if (conf.fail_on_info && c.result()=="FAILED") || (c.top_severity() >Level::Info) { 1 } else { 0 }).sum()
    };
    if let Some(f) = output_file{
        let print = if json {
            serde_json::to_string(&scan).unwrap()
        }else{
            scan.print_to_file_string()
        };
        write_to_file(&f,print);
    }
    failed
}
/*
pub fn _run_active_swagger_scan<T>(scan_try:Result<ActiveScan<T>,&'static str>,_verbosity:u8,_output_file:&str,_auth:&SAuth,_tp:ActiveScanType)
where T:OAS+Serialize+for<'de> Deserialize<'de>{
    let mut scan = match scan_try{
        Ok(s)=>s,
        Err(e)=>{
            print_err(e);
            return;
        },
    };
    executor::block_on(scan.run(tp,auth));
    //scan.print(verbosity);
    //let print = scan.print_to_file_string();
    //write_to_file(output_file,print);
}*/
pub fn run_swagger(file:&str,verbosity:u8,output_file:Option<String>,/*_auth:&SAuth,_active:bool,_active_scan_type:ActiveScanType*/config:&str,json:bool)->i8{
    let config = if let Some(c) = Config::from_file(config){
        c
    }else{
        //println!("No config file was loaded to the scan, default configuration is being used");
        Config::default()
    };
    let (value,version) = if let Some((v1,v2)) = get_oas_value_version(file){ (v1,v2)} else { return -1; };
    if version.starts_with("3.0"){
        run_passive_swagger_scan::<Swagger>(PassiveSwaggerScan::<Swagger>::new(value),verbosity,output_file,config,json)
        //if active{
            //run_active_swagger_scan::<Swagger>(ActiveScan::<Swagger>::new(swagger_value),verbosity,output_file,auth,active_scan_type);
        //}
    }else if version.starts_with("3.1"){
        run_passive_swagger_scan::<OAS3_1>(PassiveSwaggerScan::<OAS3_1>::new(value),verbosity,output_file,config,json)
        //if active{
            //run_active_swagger_scan::<OAS3_1>(ActiveScan::<OAS3_1>::new(swagger_value),verbosity,output_file,auth,active_scan_type);
        //}
    }else{
        print_err("Unsupported OpenAPI specification version");
        -1
    }
}
pub fn param_table(file:&str,param:Option<String>){
    let (value,version) = if let Some((v1,v2)) = get_oas_value_version(file){ (v1,v2)} else { return; };
    if version.starts_with("3.0"){
        let table = ParamTable::new::<Swagger>(&value);
        if let Some(p) = param{
            table.named_param(&p).print(); 
        }else{
            table.print();
        }
    }else if version.starts_with("3.1"){
        let table = ParamTable::new::<OAS3_1>(&value);
        if let Some(p) = param{
            table.named_param(&p).print(); 
        }else{
            table.print();
        }
    }else{
        print_err("Unsupported OpenAPI specification version");
    }
}

pub fn ep_table(file:&str,path:Option<String>){
    let (value,version) = if let Some((v1,v2)) = get_oas_value_version(file){ (v1,v2)} else { return; };
    if version.starts_with("3.0"){
        let table = EpTable::new::<Swagger>(&value);
        if let Some(p) = path{
            table.path_only(&p).print();
        }else{
            table.print();
        }
    }else if version.starts_with("3.1"){
        let table = EpTable::new::<OAS3_1>(&value);
        if let Some(p) = path{
            table.path_only(&p).print();
        }else{
            table.print();
        }
    }else{
        print_err("Unsupported OpenAPI specification version");
    }
}

pub fn map(logs_file: String, output: String,hint_file:Option<String>) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            print_err(&format!("Failed reading logs file \"{}\"", &logs_file));
            return;
        }
    };
    let mut digest = Digest::default();
    let sessions = get_sessions(&logs);
    if !sessions.is_empty() {
        println!("{}", "Starts mapping...".green());
        if let Some(h_f) = hint_file{
            let oas_hint:OAS3_1 = match read_file(&h_f){
                Some(c) => match serde_json::from_str(&c){
                    Ok(s) => s,
                    Err(e)=>{
                        print_err(&e.to_string());
                        print_err("Failed parsing the OpenAPI hint file");
                        return;
                    }
                },
                None=>{
                    print_err(&format!("Failed reading hint file \"{}\"", &h_f));
                    return;
                }
            };
            let hint_servers = oas_hint.servers().unwrap_or_default().iter().filter_map(|s| {
                if let Ok(u) = Url::parse(&s.url){
                    if u.path().trim() != ""{
                        Some(u.path().trim().to_string())
                    }else{
                        None
                    }
                }else{
                    Some(s.url.clone())
                }
            }).collect::<Vec<String>>();
            let hint = oas_hint.get_paths().iter().flat_map(|(p,_)| hint_servers.iter().map(|s| format!("{}/{}",s,p)).collect::<Vec<String>>()).collect();
            digest.load_vec_session(sessions,Some(hint));
        }else{
            digest.load_vec_session(sessions,None);
        }
        let map_string = match serde_json::to_string(&digest) {
            Ok(r) => r,
            Err(_) => {
                print_err("Failed parsing digest");
                return;
            }
        };
        write_to_file(&format!("{}_checkpoint.json", output), map_string);
        write_to_file(
            &format!("{}.json",output),
            parse_map_file(digest).unwrap_or_else(|_| {
                print_err("Failed parsing digest into web map");
                String::new()
            }),
        );
        println!("{}", format!("Mapping Done! Saved as \"{}.json\", you can upload and view it at https://www.blstsecurity.com/cherrybomb/Visualizer", output).green());
    } else {
        print_err("Something went wrong while mapping, check the errors above");
    }
}
pub fn prepare_attacker(mut url: String, map_file: String) {
    let d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    match Url::parse(&url) {
        Ok(_) => {
            if !(url.contains("https://") || url.contains("http://")) {
                url.push_str("https://");
            }
        }
        Err(_) => {
            print_err(&format!("Invalid url \"{}\"", url));
            return;
        }
    }
    let groups = prepare(d_map, url);
    for (i, g) in groups.iter().enumerate() {
        println!("Population number {:?} , endpoints: {:?}", i, g);
    }
}

pub async fn attack_domain(
    map_file: String,
    decide_file: String,
    pop: usize,
    gen: usize,
    verbosity: Verbosity,
    headers: Vec<Header>,
    auth: Authorization,
) {
    let d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    println!("{}", "Attacking...".purple().bold());
    for _ in 0..gen {
        println!("{}", format!("Generation: {}", gen).purple().bold());
        match attack(
            pop,
            verbosity,
            &format!("{}.json", decide_file),
            &headers,
            &auth,
        )
        .await
        {
            Ok(vec_sessions) => {
                let anomalys = decide(d_map.clone(), vec_sessions, None);
                let mut a1 = vec![];
                let mut a2 = vec![];
                println!("{}", "Decider starting\nSearching for anomalys...".bold());
                for a in &anomalys {
                    match a {
                        (Some(r), v) => {
                            a1.push(Some(r.clone()));
                            a2.push(v.clone());
                            let anomaly_score: u16 = v.iter().sum();
                            println!("Anomaly score: {}", anomaly_score.to_string().bold());
                            match &r.endpoint {
                                Some(e) => {
                                    println!("{:?}", r.session.token);
                                    for ep in &r.session.req_res {
                                        if ep == e {
                                            println!("{}", format!("{}", ep).red());
                                        } else {
                                            println!("{}", format!("{}", ep).green());
                                        }
                                    }
                                }
                                None => {
                                    println!(
                                        "{}",
                                        (&serde_json::to_string(&r.session).unwrap()).yellow()
                                    );
                                }
                            }
                        }
                        (None, v) => {
                            a1.push(None);
                            a2.push(v.clone());
                        }
                    }
                }
                refit(pop, a1, a2);
                println!("{}", "Decider done!".bold());
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    }
    println!("{}", "Attcker done!".purple().bold());
}
pub fn decide_sessions(logs_file: String, map_file: String) {
    let vec_sessions = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            print_err(&format!("Failed reading logs file \"{}\"", &logs_file));
            return;
        }
    };
    let d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    let anomalys = decide(d_map, get_sessions(&vec_sessions), None);
    let mut a1 = vec![];
    let mut a2 = vec![];
    println!("{}", "Decider starting\nSearching for anomalys...".bold());
    for a in &anomalys {
        match a {
            (Some(r), v) => {
                a1.push(Some(r.clone()));
                a2.push(v.clone());
                let anomaly_score: u16 = v.iter().sum();
                println!("Anomaly score: {}", anomaly_score.to_string().bold());
                match &r.endpoint {
                    Some(e) => {
                        println!("{:?}", r.session.token);
                        for ep in &r.session.req_res {
                            if ep == e {
                                println!("{}", format!("{}", ep).red());
                            } else {
                                println!("{}", format!("{}", ep).green());
                            }
                        }
                    }
                    None => {
                        println!("{}", (&serde_json::to_string(&r.session).unwrap()).yellow());
                    }
                }
            }
            (None, v) => {
                a1.push(None);
                a2.push(v.clone());
            }
        }
    }
    println!("{}", "Decider done!".bold());
}

pub fn load(logs_file: String, map_file: String) {
    let logs = match read_file(&logs_file) {
        Some(r) => r,
        None => {
            print_err(&format!("Failed reading logs file \"{}\"", &logs_file));
            return;
        }
    };
    let mut d_map: Digest = match read_file(&format!("{}_checkpoint.json", map_file)) {
        Some(s_map) => match serde_json::from_str(&s_map) {
            Ok(r) => r,
            Err(e) => {
                print_err(&format!("Failed getting parsing map to digest, {:?}", e));
                return;
            }
        },
        None => {
            print_err(&format!(
                "Failed reading map file \"{}_checkpoint\"",
                &map_file
            ));
            return;
        }
    };
    let sessions = get_sessions(&logs);
    if !sessions.is_empty() {
        println!("{}", "Starts mapping...".green());
        d_map.load_vec_session(sessions,None);
        let map_string = match serde_json::to_string(&d_map) {
            Ok(r) => r,
            Err(_) => {
                print_err("Failed parsing digest");
                return;
            }
        };
        write_to_file(&format!("{}_checkpoint.json", map_file), map_string);
        write_to_file(
            &format!("{}.json",map_file),
            parse_map_file(d_map).unwrap_or_else(|_| {
                print_err("Failed parsing digest into web map");
                String::new()
            }),
        );
        println!("{}", format!("Mapping Done! Saved as \"{}.json\", you can upload and view it at https://www.blstsecurity.com/cherrybomb/Visualizer", map_file).green());
    } else {
        print_err("Something went wrong while mapping, check the errors above");
    }
}
