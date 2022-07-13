use swagger::*;

#[tokio::main]
async fn main() {
    // let f_name = "/home/raz/Downloads/juice.yml";
    let f_name = "/home/nathan/Documents/POC/Cherry/openapi.json";
    //let _swagger_str:Swagger = serde_json::from_str(&std::fs::read_to_string(f_name).unwrap()).unwrap();
    //let f_names = ["swagger2.json","swagger3.json","swagger4.json","swagger5.json","swagger6.json","swagger7.json"];
    //for f_name in f_names{
    let swagger_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(f_name).unwrap()).unwrap();

    // let mut a = PassiveSwaggerScan::<OAS3_1>::new(swagger_value.clone()).unwrap();
    // a.run(PassiveScanType::Full);
    // a.print(1);


    let mut a = ActiveScan::<OAS3_1>::new(swagger_value).unwrap();
    use futures::executor;
    executor::block_on(a.run(ActiveScanType::Full,&Authorization::None));
  //  a.print(0);

    // a.print(0);

}
