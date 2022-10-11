use swagger::*;

#[tokio::main]
async fn main() {
    let f_name = "/home/nathan/Documents/POC/Cherry/petstore.json";
    let swagger_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(f_name).unwrap()).unwrap();

    let mut a = PassiveSwaggerScan::<OAS3_1>::new(swagger_value.clone()).unwrap();
    a.run(PassiveScanType::Full);
    //a.print(1);
    //  a.print(0);

    let a = ParamTable::new::<OAS3_1>(&swagger_value);
    //a.print();

    let a = EpTable::new::<OAS3_1>(&swagger_value);
    //a.print();

    let mut a = ActiveScan::<OAS3_1>::new(swagger_value).unwrap();
    use futures::executor;
    executor::block_on(a.run(ActiveScanType::Full, &Authorization::None));
    a.print(1);
   // a.print(0);
}
