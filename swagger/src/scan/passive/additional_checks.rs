use std::collections::HashSet;

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
                        Level::Low,
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

    fn check_schema(&self, schema: SchemaRef, alerts: &mut Vec<Alert>, path: String) {
        if let Some(format_value) = schema.inner(&self.swagger_value).format {
            if format_value.eq("int32") || format_value.eq("int64") {
                if let Some(schema_type) = schema.inner(&self.swagger_value).schema_type {
                    if schema_type.as_str() == "number" {
                        let _ = &alerts.push(Alert::new(
                            Level::Info,
                            "Type has to be an integer",
                            format!("swagger path:{} schema:{:?}", path, schema),
                        ));
                    };
                }
            }
        }
        
    }

    pub fn check_int_type(&self) -> Vec<Alert> {
        /// this function check  the get paramter schema all component and response and request body that does not use component
        let mut hashset_compo_name: HashSet<String> = HashSet::new();

        let mut alerts: Vec<Alert> = vec![];
        let schemas = &self
            .swagger
            .components()
            .unwrap()
            .schemas
            .unwrap_or_default();
        for (key, value) in schemas {
            let name = format!("#/components/schemas/{}", key);
            hashset_compo_name.insert(key.to_string());
            println!("THis is the key {:?}", name);
            if let Some(propert) = value.inner(&self.swagger_value).properties {
                for (key, schemaref) in propert {
                    if let Some(format_value) = schemaref.inner(&self.swagger_value).format {
                        if format_value.eq("int32") || format_value.eq("int64") {
                            if let Some(schema_type) =
                                schemaref.inner(&self.swagger_value).schema_type
                            {
                                if schema_type.as_str() == "number" {
                                    alerts.push(Alert::new(
                                        Level::Info,
                                        "Type has to be an integer",
                                        format!("component name: {:?}", key),
                                    ));
                                };
                            }
                        }
                    }
                }
            }
        }
        for (path, item) in &self.swagger.get_paths() {
            for (_m, op) in item.get_ops() {
                for i in op.params() {
                    //schema get parameter

                    let o = i.inner(&self.swagger_value).schema.unwrap();
                    let p = match o {
                        SchemaRef::Ref(value_ref) => value_ref.param_ref.to_string(),
                        SchemaRef::Schema(_v) => "None".to_string(),
                    };
                    if !hashset_compo_name.contains(&p) {
                        //if op param and not reference to copmenebt

                        if let Some(schema) = i.inner(&self.swagger_value).schema {
                            self.check_schema(schema, &mut alerts, path.clone());
                        }
                    }
                }

                for (_key, value) in op.responses() {
                    if let Some(schema) = value.inner(&self.swagger_value).content {
                        for (_key, mediatype) in schema {
                            if let Some(schema) = mediatype.schema {
                                match &schema {
                                    SchemaRef::Ref(_) => (),

                                    SchemaRef::Schema(_) => {
                                        if let Some(propertie) =
                                            schema.inner(&self.swagger_value).properties
                                        {
                                            for (_key, schema_ref) in propertie {
                                                self.check_schema(
                                                    schema_ref,
                                                    &mut alerts,
                                                    path.clone(),
                                                );
                                            }
                                        }
                                    }
                                };

                                // self.check_schema(schema, &mut alerts, path.clone());
                            }
                        }
                    }
                }

                if let Some(request_body) = op.request_body.as_ref() {
                    //request body
                    for (_key, value) in request_body.inner(&self.swagger_value).content {
                        if let Some(schema) = value.schema {
                            match &schema {
                                SchemaRef::Ref(_) => (),
                                SchemaRef::Schema(_) => {
                                    if let Some(propertie) =
                                        schema.inner(&self.swagger_value).properties
                                    {
                                        for (_key, schema_ref) in propertie {
                                            self.check_schema(
                                                schema_ref,
                                                &mut alerts,
                                                path.clone(),
                                            );
                                        }
                                    }
                                }
                            };
                        }
                    }
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
