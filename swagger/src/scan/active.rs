use super::*;

struct ActiveSwaggerScan{
    swagger:Swagger,
    swagger_value:Value,
    alerts:Vec<Alert>,
}
impl ActiveSwaggerScan{
    pub fn run(&self)->Vec<Alert>{
        vec![]
    }
    pub fn rule1(&self){

    }
}
