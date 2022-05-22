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
        let list_contentype: Vec<&str> = vec!["application/java-archive", "application/json", "application/xml", 
        "multipart/form-data", "application/EDI-X12", "application/EDIFACT", "application/javascript", 
        "application/octet-stream", "application/ogg", "application/pdf", "application/pdf", "application/xhtml+xml", 
        "application/x-shockwave-flash", "application/json", "application/ld+json", "application/xml", "application/zip",
         "application/x-www-form-urlencoded", "image/gif", "image/jpeg", "image/png", "image/tiff", "image/vnd.microsoft.icon", 
         "image/x-icon", "image/vnd.djvu", "image/svg+xml", "text/css", "text/csv", "text/html", "text/plain", "text/xml", 
         "multipart/mixed", "multipart/alternative", "multipart/related", "multipart/form-data"];

        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){
                println!("{:?}", op);
                let res_body  = &op.responses;
                match &res_body{
                    Some(response )=>
                    {
                        for content in response.values(){
                            for content_type in  content.inner(&self.swagger_value).content.unwrap_or_default().keys(){
                                if  !list_contentype.iter().any(|v| v == &content_type){
                                    alerts.push(Alert::new(Level::Info,"Not a valid content-type",format!("swagger path:{} method:{}",path, content_type)));
                               }  
                            }
                        }
                    }
                    None => (),
                }
                let req_body = &op.request_body;
                match &req_body {
                    Some(req_ref) => {
                        for media_type in req_ref.inner(&self.swagger_value).content.keys() {                           
                                       if  !list_contentype.iter().any(|v| v == &media_type){
                                            alerts.push(Alert::new(Level::Info,"Not a valid content-type",format!("swagger path:{} method:{}",path, media_type)));
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
