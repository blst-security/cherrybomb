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
    pub fn check_get_permissions(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){       
                if m == Method::GET{
                    match &op.security {
                        Some(x) => {
                            for i in x {
                                let y = i.values().cloned().flatten().collect::<Vec<String>>();
                                for item in y {
                                    if  !item.starts_with("read"){
                                         alerts.push(Alert::new(Level::Medium,"Request GET has to be only read permission",format!("swagger path:{} method:{}",path,m)));

                                        }
                                    }
                                }
                            },
                        None => (),
                        }
                    }
                }
            }
        alerts
    }



    

    pub fn check_put_permissions(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){       
                if m == Method::PUT{
                    match &op.security {
                        Some(x) => {
                            for i in x {
                                let y = i.values().cloned().flatten().collect::<Vec<String>>();
                                for item in y {
                                    if  !item.starts_with("write"){
                                         alerts.push(Alert::new(Level::Medium,"Request PUT has to be only write permission",format!("swagger path:{} method:{}",path,m)));

                                        }
                                    }
                                }
                            },
                        None => (),
                        }
                    }
                }
            }
        alerts
    }

    

    pub fn check_post_permissions(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for(m,op) in item.get_ops(){       
                if m == Method::POST{
                    match &op.security {
                        Some(x) => {
                            for i in x {
                                let y = i.values().cloned().flatten().collect::<Vec<String>>();
                                for item in y {
                                    if  !item.starts_with("write:") && !item.starts_with("read:") {
                                        alerts.push(Alert::new(Level::Low,"Request POST has to be with read and write permissions",format!("swagger path:{} method:{}",path,m)));

                                        }
                                    }
                                }
                            },
                        None => (),
                        }
                    }
                }
            }
        alerts
    }










}
