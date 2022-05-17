use super::*;

impl<T: OAS + Serialize> PassiveSwaggerScan<T> {
    pub fn check_valid_responses(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                let statuses = op
                    .responses()
                    .iter()
                    .map(|(k, _v)| k.clone())
                    .collect::<Vec<String>>();
                for status in statuses {
                    if status.parse::<u16>().is_err() && status != "default" {
                        alerts.push(Alert::new(
                            Level::Low,
                            "Responses have an ivalid or unrecognized status code",
                            format!("swagger path:{} operation:{} status:{}", path, m, status),
                        ));
                    }
                }
            }
        }
        alerts
    }
    fn get_check(security:&Option<Vec<Security>>,path:&str)->Vec<Alert>{
        let mut alerts = vec![];
        match security {
            Some(x) => {
                for i in x {
                    let y = i.values().cloned().flatten().collect::<Vec<String>>();
                    for item in y {
                        if  !item.starts_with("read"){
                            alerts.push(Alert::new(Level::Medium,"Request GET has to be only read permission",format!("swagger path:{} method:{}",path,Method::GET)));
                        }
                    }
                }
            },
            None => (),
        };
        alerts
    }
    fn put_check(security:&Option<Vec<Security>>,path:&str)->Vec<Alert>{
        let mut alerts=vec![];
        match security {
            Some(x) => {
                for i in x {
                    let y = i.values().cloned().flatten().collect::<Vec<String>>();
                    for item in y {
                        if  !item.starts_with("write"){
                            alerts.push(Alert::new(Level::Medium,"Request PUT has to be only write permission",format!("swagger path:{} method:{}",path,Method::PUT)));
                        }
                    }
                }
            },
            None => (),
        }
        alerts
    }
    fn post_check(security:&Option<Vec<Security>>,path:&str)->Vec<Alert>{
        let mut alerts=vec![];
        match security {
            Some(x) => {
                for i in x {
                    let y = i.values().cloned().flatten().collect::<Vec<String>>();
                    for item in y {
                        if  !item.starts_with("write:") && !item.starts_with("read:") {
                            alerts.push(Alert::new(Level::Low,"Request POST has to be with read and write permissions",format!("swagger path:{} method:{}",path,Method::POST)));
                        }
                    }
                }
            },
            None => (),
        }
        alerts
    }
    pub fn check_method_permissions(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){       
                match m{
                    Method::GET=>alerts.extend(Self::get_check(&op.security,path)),
                    Method::PUT=>alerts.extend(Self::put_check(&op.security,path)),
                    Method::POST=>alerts.extend(Self::post_check(&op.security,path)),
                    _=>(),
                };
            }
        }
        alerts
    }
    pub fn  check_valid_encoding(&self) ->Vec<Alert>{
        let mut list_contentype: Vec<&str> = vec!["application/json",
        "application/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain; charset=utf-8",
        "text/html",
        "application/pdf",
        "image/png"];

        let mut alerts: Vec<Alert> = vec![];
        // for i in list_contentype{
        //     println!("  {}", &i);
        // }
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){
                let req_body = &op.request_body;
                match &req_body {
                    Some(ReqRef) => {
                        for i in &op.request_body{
                           match (&i) {
                                ReqRef::Ref(_)=> println!("pop"),
                                ReqRef::Body(p) => {
                               
                                   for key in p.content.keys(){
                                       println!("{:?}",  list_contentype.iter().any(|v| v == &key));
                                       if  !list_contentype.iter().any(|v| v == &key){
                                            alerts.push(Alert::new(Level::Low,"Not a valid content-type",format!("swagger path:{} method:{}",path, key)));

                                       }                         
                                   }
                                }
                           }
                        }
                      
                    },
                    None=>(),
                }
            }      
        }
        alerts
    
    }
}
