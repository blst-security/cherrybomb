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
            println!("{}",path);
            for(m,op) in item.get_ops(){       
                if m == Method::GET{
                    match &op.security {
                        Some(x) => {
                            for i in x {
                                let y = i.values().cloned().flatten().collect::<Vec<String>>();
                                let mut flag = true;
                                for item in y {
                                    if  !item.starts_with("read"){
                                        alerts.push(Alert::new(Level::Low,"INSECURE",format!("swagger path:{} method {} has to be only READ permissions  ",path,m )))

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
