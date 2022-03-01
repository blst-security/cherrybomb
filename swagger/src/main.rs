use swagger::*;

#[tokio::main]
async fn main() {
    let f_name = "swagger3.json";
    //let _swagger_str:Swagger = serde_json::from_str(&std::fs::read_to_string(f_name).unwrap()).unwrap();
    //let f_names = ["swagger2.json","swagger3.json","swagger4.json","swagger5.json","swagger6.json","swagger7.json"];
    //for f_name in f_names{
    let swagger_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(f_name).unwrap()).unwrap();
    /*
    let version = swagger_value["openapi"].to_string().trim().replace("\"","");
    let swagger = if version.starts_with("3.1"){
        serde_json::from_str::<OAS3_1>(&std::fs::read_to_string(f_name).unwrap()).unwrap();
        println!("{} in 3.1",f_name);
    }else if version.starts_with("3.0"){
        serde_json::from_str::<Swagger>(&std::fs::read_to_string(f_name).unwrap()).unwrap();
        println!("{} in 3.0",f_name);
    }else{
        println!("{} {}",f_name,version);
    };*/
    /*let swagger =
        serde_json::from_str::<OAS3_1>(&std::fs::read_to_string(f_name).unwrap()).unwrap();*/
    //   println!("{:?}",swagger.paths.unwrap().get("/users").unwrap().get.as_ref().unwrap().security.as_ref().unwrap());
    //}
    /*
    let mut a = ActiveScan::<OAS3_1>::new(swagger_value).unwrap();
    use futures::executor;
    executor::block_on(a.run(ActiveScanType::Full,&Authorization::None));
    
    a.print(0);
    */
    let mut a = PassiveSwaggerScan::<Swagger>::new(swagger_value.clone()).unwrap();
    a.run(PassiveScanType::Full);
    //println!("{:?}",serde_json::to_string(&a).unwrap());
    a.print(1);
    let t = ParamTable::new(serde_json::from_value::<OAS3_1>(swagger_value).unwrap());
    //print_checks_table(&a);
    //print_alerts_table(&a);
    //let _sw = swagger_str.convert_to_map(swagger_value);
    //println!("{:?}",swagger_str);
    //println!("{:?}",swagger_value);
    //let swagger_str:Swagger = serde_yaml::from_str(&std::fs::read_to_string("swagger.yaml").unwrap()).unwrap();
    //println!("{:?}",swagger_str);
}
