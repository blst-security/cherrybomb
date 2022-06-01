use super::*;
const  LIST_CONTENT_TYPE: [&str;35] = ["application/java-archive", "application/json", "application/xml", 
"multipart/form-data", "application/EDI-X12", "application/EDIFACT", "application/javascript", 
"application/octet-stream", "application/ogg", "application/pdf", "application/pdf", "application/xhtml+xml", 
"application/x-shockwave-flash", "application/json", "application/ld+json", "application/xml", "application/zip",
 "application/x-www-form-urlencoded", "image/gif", "image/jpeg", "image/png", "image/tiff", "image/vnd.microsoft.icon", 
 "image/x-icon", "image/vnd.djvu", "image/svg+xml", "text/css", "text/csv", "text/html", "text/plain", "text/xml", 
 "multipart/mixed", "multipart/alternative", "multipart/related", "multipart/form-data"];

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
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){
                let res_body  = &op.responses;
                match &res_body{
                    Some(response )=>
                        {
                        for content in response.values(){
                            for content_type in  content.inner(&self.swagger_value).content.unwrap_or_default().keys(){
                                if  !LIST_CONTENT_TYPE.contains(&content_type.as_str()){
                                    alerts.push(Alert::new(Level::Info,"This content type is very uncommon or invalid please check it",format!("swagger path:{} method:{}",path, content_type)));
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
                            if  !LIST_CONTENT_TYPE.contains(&media_type.as_str()){
                                alerts.push(Alert::new(Level::Info,"This content type is very uncommon or invalid please check it",format!("swagger path:{} method:{}",path, media_type)));
                            }  // The Content-Type used is uncommon or invalid, this might be a misconfiguration.
                        }
                    },
                    None=>(),
                }
            }      
        }
        alerts
    
    }
    pub fn  check_example(&self) ->Vec<Alert>{
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){
                match &op.request_body {
                    Some(refer) => {
                         let hash =refer.inner({&Value::Null}).content;
                         for i in hash.values(){
                             if i.examples.as_ref() == None {
                                alerts.push(Alert::new(Level::Info,"This request body or this response has not example!",format!("swagger path:{} method:{}",path, m)));
                            }
                         }
                    }
                    None => {}
                }
                if let Some(content) = &op.responses.as_ref()
                {
                    for i in content.values(){
                        if let  Some(val) = i.inner({&Value::Null}).content{
                           for x in val.values() {
                               println!("{:?}", x.examples);
                               if x.examples== None {
                                alerts.push(Alert::new(Level::Info,"This request body or this response has not example!",format!("swagger path:{} method:{}",path, m)));
                               }
                           }
                        }
                    }
                }   
            }
        }
        alerts
    }

}
