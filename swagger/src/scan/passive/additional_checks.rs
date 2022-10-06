use super::*;

impl<T: OAS + Serialize> PassiveSwaggerScan<T> {
    pub fn check_valid_responses(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                let statuses = op.responses().keys().cloned().collect::<Vec<String>>();
                for status in statuses {
                    if let Ok(res_code) = status.parse::<u16>() {
                        if !(100..600).contains(&res_code) {
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
                            alerts.push(Alert::new(
                                Level::Medium,
                                "Request GET has to be only read permission",
                                format!("swagger path:{} method:{}", path, Method::GET),
                            ));
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
                            alerts.push(Alert::new(
                                Level::Medium,
                                "Request PUT has to be only write permission",
                                format!("swagger path:{} method:{}", path, Method::PUT),
                            ));
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
                            alerts.push(Alert::new(
                                Level::Low,
                                "Request POST has to be with read and write permissions",
                                format!("swagger path:{} method:{}", path, Method::POST),
                            ));
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
            if item.get_ops().is_empty() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Path has no operations",
                    format!("swagger path:{} ", path),
                ));
            }
        }
        alerts
    }

    pub fn check_valid_encoding(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (_m, op) in item.get_ops() {
                if let Some(req_body) = &op.request_body {
                    req_body
                        .inner(&self.swagger_value)
                        .content
                        .keys()
                        .for_each(|c_t| {
                            if !LIST_CONTENT_TYPE.contains(&c_t.as_str()) {
                                alerts.push(Alert::new(
                                    Level::Low,
                                    "Request body has an invalid content type",
                                    format!("swagger path:{} content type:{}", path, c_t),
                                ))
                            }
                        });
                }
            }
        }
        alerts
    }

    pub fn check_description(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                if op.description.is_none() {
                    alerts.push(Alert::new(
                        Level::Info,
                        "Operation has no description",
                        format!("swagger path:{} operation:{}", path, m),
                    ));
                } else if op.description.as_ref().unwrap().is_empty() {
                    alerts.push(Alert::new(
                        Level::Low,
                        "Operation has an empty description",
                        format!("swagger path:{} operation:{}", path, m),
                    ));
                }
            }
        }
        alerts
    }

    pub fn check_contains_response(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                if op.responses.is_none() || op.responses.as_ref().unwrap().is_empty() {
                    alerts.push(Alert::new(
                        Level::Low,
                        "Operation has no responses",
                        format!("swagger path:{} operation:{}", path, m),
                    ));
                }
            }
        }
        alerts
    }
}

const LIST_CONTENT_TYPE: [&str; 35] = [
    "application/java-archive",
    "application/json",
    "application/xml",
    "multipart/form-data",
    "application/EDI-X12",
    "application/EDIFACT",
    "application/javascript",
    "application/octet-stream",
    "application/ogg",
    "application/pdf",
    "application/pdf",
    "application/xhtml+xml",
    "application/x-shockwave-flash",
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/zip",
    "application/x-www-form-urlencoded",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/vnd.microsoft.icon",
    "image/x-icon",
    "image/vnd.djvu",
    "image/svg+xml",
    "text/css",
    "text/csv",
    "text/html",
    "text/plain",
    "text/xml",
    "multipart/mixed",
    "multipart/alternative",
    "multipart/related",
    "multipart/form-data",
];
