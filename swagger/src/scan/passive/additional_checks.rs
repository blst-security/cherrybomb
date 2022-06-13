use super::*;

const  LIST_CONTENT_TYPE: [&str;35] = ["application/java-archive", &"application/json", "application/xml",
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
                    .keys()
                    .cloned()
                    .collect::<Vec<String>>();

                for status in statuses {
                    if let Ok(res) = status.parse::<u16>() {
                        if res < 100 || res > 599 {
                            alerts.push(Alert::new(
                                Level::Low,
                                "Responses have an invalid or unrecognized status code",
                                format!("swagger path:{} operation:{} status:{}", path, m, status),
                            ));
                        }
                    } else if status != "default" {
                        alerts.push(Alert::new(
                            Level::Low,
                            "Responses have an invalid or unrecognized status code",
                            format!("swagger path:{} operation:{} status:{}", path, m, status),
                        ));
                    }
                }
            }
        }
        alerts
    }
    fn get_check(security: &Option<Vec<Security>>, path: &str) -> Vec<Alert> {
        let mut alerts = vec![];
        match security {
            Some(x) => {
                for i in x {
                    let y = i.values().flatten().cloned().collect::<Vec<String>>();
                    for item in y {
                        if !item.starts_with("read") {
                            alerts.push(Alert::new(Level::Medium, "Request GET has to be only read permission", format!("swagger path:{} method:{}", path, Method::GET)));
                        }
                    }
                }
            }
            None => (),
        };
        alerts
    }
    fn put_check(security: &Option<Vec<Security>>, path: &str) -> Vec<Alert> {
        let mut alerts = vec![];
        match security {
            Some(x) => {
                for i in x {
                    let y = i.values().flatten().cloned().collect::<Vec<String>>();
                    for item in y {
                        if !item.starts_with("write") {
                            alerts.push(Alert::new(Level::Medium, "Request PUT has to be only write permission", format!("swagger path:{} method:{}", path, Method::PUT)));
                        }
                    }
                }
            }
            None => (),
        }
        alerts
    }
    fn post_check(security: &Option<Vec<Security>>, path: &str) -> Vec<Alert> {
        let mut alerts = vec![];
        match security {
            Some(x) => {
                for i in x {
                    let y = i.values().flatten().cloned().collect::<Vec<String>>();
                    for item in y {
                        if !item.starts_with("write:") && !item.starts_with("read:") {
                            alerts.push(Alert::new(Level::Low, "Request POST has to be with read and write permissions", format!("swagger path:{} method:{}", path, Method::POST)));
                        }
                    }
                }
            }
            None => (),
        }
        alerts
    }
    pub fn check_method_permissions(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                match m {
                    Method::GET => alerts.extend(Self::get_check(&op.security, path)),
                    Method::PUT => alerts.extend(Self::put_check(&op.security, path)),
                    Method::POST => alerts.extend(Self::post_check(&op.security, path)),
                    _ => (),
                };
            }
        }
        alerts
    }

    pub fn check_contains_operation(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            if item.get_ops().len() == 0 {
                alerts.push(Alert::new(Level::Low, "Path has no operations"
                 , format!("swagger path:{} ", path)));
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
                    Some(response )=>{
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
                        if let  Some(val) = i.inner(&self.swagger_value).content{
                            for x in val.values() {
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

    pub fn check_descriptions (&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){
                match &op.description {
                    Some(value) => {
                        if value.to_string() == "" || value.to_string() == " " {
                            alerts.push(Alert::new(Level::Info,"This endpoint has not description!",format!("swagger path:{} method:{}",path, m)));
                        }
                    },
                    None =>   alerts.push(Alert::new(Level::Info,"This endpoint has not description!",format!("swagger path:{} method:{}",path, m))),
                }
                if m.to_string() == "POST" || m.to_string() =="PUT" {
                    match &op.request_body {
                        Some(value)=> {
                            if value.inner(&self.swagger_value).description.unwrap_or_default().trim() == "" {
                                alerts.push(Alert::new(Level::Info,"This request body  for this ",format!("swagger path:{} method:{} has not description",path, m)))
                            }
                        },
                        None=> alerts.push(Alert::new(Level::Info,"No description for for this ",format!("method:{} swagger path:{} has not description",m, path)))
                        ,
                    }
                }

                match &op.responses {
                    Some(value) => {
                        for i in value.values() {
                            let resp_body_descrip = i.inner(&Value::Null).description;
                            if resp_body_descrip == "" && resp_body_descrip == " " {
                                alerts.push(Alert::new(Level::Info,"This response for this ",format!("swagger path:{} method:{} has not description",path, m)))
                            }
                        }
                    },
                    None =>  alerts.push(Alert::new(Level::Info,"This response for this ",format!("swagger path:{} method:{} has not description",path, m))),
                }
            }
        }
        alerts
    }

    pub fn check_body_request (&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){
                if m.to_string() == "POST" || m.to_string() =="PUT" {
                    match &op.request_body {
                        Some(value)=> (),
                        None=> alerts.push(Alert::new(Level::Info,"No request body for this ",format!("method:{} swagger path:{}.",m, path))),
                    }
                }
            }
        }
        alerts
    }

}
