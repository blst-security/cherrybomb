use super::*;
use swagger::scan::active::{ActiveScan, ActiveScanType};
use swagger::scan::passive::PassiveSwaggerScan;
use swagger::scan::Level;
use swagger::{Authorization, Check, EpTable, ParamTable, PassiveScanType, Swagger, OAS, OAS3_1};

pub fn run_passive_swagger_scan<T>(
    scan_try: Result<PassiveSwaggerScan<T>, &'static str>,
    verbosity: u8,
    output_file: Option<String>,
    passive_scan_type: PassiveScanType,
    json: bool,
) -> Result<i8, &'static str>
where
    T: OAS + Serialize + for<'de> Deserialize<'de> + std::fmt::Debug,
{
    let mut scan = match scan_try {
        Ok(s) => s,
        Err(e) => {
            return Err(e);
        }
    };
    scan.run(passive_scan_type);
    if json {
        println!("{}", serde_json::to_string(&scan).unwrap());
    } else {
        scan.print(verbosity);
    }
    let failed = scan.passive_checks.iter().any(|c| c.result() == "FAILED"); //TODO support minimum level failure
    if let Some(f) = output_file {
        let print = if json {
            serde_json::to_string(&scan).unwrap()
        } else {
            scan.print_to_file_string()
        };
        write_to_file(&f, print);
    }
    if failed {
        Ok(101)
    } else {
        Ok(0)
    }
}

pub async fn run_active_swagger_scan<T>(
    scan_try: Result<ActiveScan<T>, &'static str>,
    verbosity: u8,
    output_file: Option<String>,
    auth: Authorization,
    scan_type: ActiveScanType,
) -> Result<i8, &'static str>
where
    T: OAS + Serialize + for<'de> Deserialize<'de> + std::fmt::Debug,
{
    let mut scan = match scan_try {
        Ok(s) => s,
        Err(e) => {
            return Err(e);
        }
    };
    scan.run(scan_type, &auth).await;
    scan.print(verbosity);
    let failed = scan
        .checks
        .iter()
        .any(|c| (c.result() == "FAILED") || (c.top_severity() > Level::Info));
    if let Some(f) = output_file {
        let print = scan.print_to_file_string();
        write_to_file(&f, print);
    }
    if failed {
        Ok(101)
    } else {
        Ok(0)
    }
}

pub async fn run_swagger(
    file: &str,
    verbosity: u8,
    output_file: Option<String>,
    auth: Authorization,
    active_scan_type: ActiveScanType,
    passive_scan_type: PassiveScanType,
    json: bool,
) -> i8 {
    let (value, version) = if let Some((v1, v2)) = get_oas_value_version(file) {
        (v1, v2)
    } else {
        return -1;
    };
    if version.starts_with("3.") {
        let passive_result = run_passive_swagger_scan::<OAS3_1>(
            PassiveSwaggerScan::<OAS3_1>::new(value.clone()),
            verbosity,
            output_file.clone(),
            passive_scan_type,
            json,
        );
        if let Err(e) = passive_result {
            print_err(e);
            return -1;
        }
        let active_result = run_active_swagger_scan::<OAS3_1>(
            ActiveScan::<OAS3_1>::new(value.clone()),
            verbosity,
            output_file.clone(),
            auth,
            active_scan_type,
        )
        .await;
        if let Err(e) = active_result {
            print_err(e);
            return -1;
        }
        if let Ok(p_r) = passive_result && let Ok(a_r) = active_result{
            if p_r == 0 && a_r == 0{
                0
            }
            else {
                101
            }
        } else {
           -1
        }
    } else {
        print_err("Unsupported OpenAPI specification version");
        -1
    }
}

pub fn param_table(file: &str, param: Option<String>) {
    let (value, version) = if let Some((v1, v2)) = get_oas_value_version(file) {
        (v1, v2)
    } else {
        return;
    };
    if version.starts_with("3.0") {
        let table = ParamTable::new::<Swagger>(&value);
        if let Some(p) = param {
            table.named_param(&p).print();
        } else {
            table.print();
        }
    } else if version.starts_with("3.1") {
        let table = ParamTable::new::<OAS3_1>(&value);
        if let Some(p) = param {
            table.named_param(&p).print();
        } else {
            table.print();
        }
    } else {
        print_err("Unsupported OpenAPI specification version");
    }
}

pub fn ep_table(file: &str, path: Option<String>) {
    let (value, version) = if let Some((v1, v2)) = get_oas_value_version(file) {
        (v1, v2)
    } else {
        return;
    };
    if version.starts_with("3.0") {
        let table = EpTable::new::<Swagger>(&value);
        if let Some(p) = path {
            table.path_only(&p).print();
        } else {
            table.print();
        }
    } else if version.starts_with("3.1") {
        let table = EpTable::new::<OAS3_1>(&value);
        if let Some(p) = path {
            table.path_only(&p).print();
        } else {
            table.print();
        }
    } else {
        print_err("Unsupported OpenAPI specification version");
    }
}
