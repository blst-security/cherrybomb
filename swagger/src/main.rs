use swagger::*;

#[tokio::main]
async fn main() {
    let f_name = "/home/raz/Downloads/crapi.json";
    let swagger_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(f_name).unwrap()).unwrap();

    let mut a = PassiveSwaggerScan::<OAS3_1>::new(swagger_value.clone()).unwrap();
    a.run(PassiveScanType::Full);
    a.print(1);


    let mut a = ActiveScan::<OAS3_1>::new(swagger_value).unwrap();
    use futures::executor;
    executor::block_on(a.run(ActiveScanType::Full,&Authorization::None));
    a.print(0);
}
