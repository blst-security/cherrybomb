use super::passive_scanner::PassiveSwaggerScan;
use crate::scan::passive::utils::*;
use crate::scan::*;
use cherrybomb_oas::legacy::legacy_oas::OAS;
use std::collections::HashSet;

pub trait PassiveGeneralScan {
    fn check_server_url(&self) -> Vec<Alert>;
    fn check_additional_properties(&self) -> Vec<Alert>;
    fn check_successes(&self) -> Vec<Alert>;
    fn check_default_response(&self) -> Vec<Alert>;
    fn check_response_body_schema(&self) -> Vec<Alert>;
    fn example_inconsistant_schema(&self) -> Vec<Alert>;
    fn check_default_type(&self) -> Vec<Alert>;
    fn check_enum_type(&self) -> Vec<Alert>;
    fn check_required_undefined(&self) -> Vec<Alert>;
    fn check_unused_schema(&self) -> Vec<Alert>;
}

///Rule fucntions implementation
impl<T: OAS + Serialize> PassiveGeneralScan for PassiveSwaggerScan<T> {
    ///Can raise no https alert and invalid url in server alert
    fn check_server_url(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut server_addrs = HashSet::new();
        if let Some(servers) = &self.swagger.servers() {
            alerts.extend(check_servers_for_server_url_rule(
                servers,
                "swagger root servers",
                &mut server_addrs,
            ));
        }
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                if let Some(servers) = &op.servers {
                    alerts.extend(check_servers_for_server_url_rule(
                        servers,
                        &format!("swagger {path} {m} servers"),
                        &mut server_addrs,
                    ));
                }
            }
        }
        //println!("{:?}",alerts);
        alerts
    }
    fn check_successes(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        for (path, item) in &self.swagger.get_paths() {
            for (m, op) in item.get_ops() {
                let statuses = op.responses().keys().cloned().collect::<Vec<String>>();
                let mut found = false;
                for status in statuses {
                    if let Ok(s) = status.parse::<u16>() {
                        if (200..300).contains(&s) {
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    alerts.push(Alert::new(
                        Level::Low,
                        "Responses have no success status(2XX)",
                        format!("swagger path:{path} operation:{m}"),
                    ));
                }
            }
        }
        alerts
    }
    fn check_additional_properties(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        if let Some(comps) = &self.swagger.components() {
            if let Some(schemas) = &comps.schemas {
                for (name, schema) in schemas {
                    alerts.extend(additional_properties_test(
                        &schema.inner(&self.swagger_value),
                        format!("swagger root components schema:{name}"),
                    ))
                }
            }
        }
        alerts
    }
    fn check_default_response(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let message = "No default response defined";
        for (responses, location) in get_responses(&self.swagger) {
            if responses.get("default").is_none() {
                alerts.push(Alert::new(Level::Low, message, location));
            }
        }
        //println!("{:?}",alerts);
        alerts
    }
    fn check_response_body_schema(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let message = "Response body doesn't have a schema";
        for (responses, location) in get_responses(&self.swagger) {
            for (status, response) in responses {
                if let Some(content) = response.inner(&self.swagger_value).content {
                    for (name, m_t) in content {
                        if m_t.schema.is_none() {
                            alerts.push(Alert::new(
                                Level::Medium,
                                message,
                                format!("{location} status:{status} media type:{name}"),
                            ));
                        }
                    }
                }
            }
        }
        alerts
    }
    fn example_inconsistant_schema(&self) -> Vec<Alert> {
        vec![]
    }
    fn check_default_type(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        for (param, loc) in get_params(&self.swagger, &self.swagger_value) {
            alerts.extend(param_default_rec(&param, loc));
        }
        alerts
    }
    fn check_enum_type(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        for (param, loc) in get_params(&self.swagger, &self.swagger_value) {
            alerts.extend(param_enum_rec(&param, loc));
        }
        alerts
    }
    fn check_required_undefined(&self) -> Vec<Alert> {
        vec![]
    }
    fn check_unused_schema(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let swagger_str = serde_json::to_string(&self.swagger).unwrap();
        if let Some(comps) = &self.swagger.components() {
            if let Some(schemas) = &comps.schemas {
                for name in schemas.keys() {
                    let schema_path = format!("#/components/schemas/{name}");
                    if !swagger_str.contains(&schema_path) {
                        alerts.push(Alert::new(
                            Level::Info,
                            "Schema is defined but never used",
                            format!("swagger root components schema:{name}"),
                        ));
                    }
                }
            }
        }
        alerts
    }
}
