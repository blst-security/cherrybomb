use super::passive_scanner::*;
use crate::scan::*;
use cherrybomb_oas::legacy::legacy_oas::*;
use cherrybomb_oas::legacy::refs::*;
use cherrybomb_oas::legacy::utils::*;
use serde::Serialize;
use std::collections::HashSet;

impl<T: OAS + Serialize> PassiveSwaggerScan<T> {
    fn check_schema(&self, schema: SchemaRef, alerts: &mut Vec<Alert>, path: String) {
        // The purpose of the check is to ensure that the type number correspond to "integer" format and type number has a "float" format
        //this function check the correct format for corresponding types
        if let Some(format_value) = schema.inner(&self.swagger_value).format {
            if format_value.eq("int32") || format_value.eq("int64") {
                if let Some(schema_type) = schema.inner(&self.swagger_value).schema_type {
                    if schema_type.as_str() != "integer" {
                        let _ = &alerts.push(Alert::new(
                            Level::Info,
                            "Type integer must have a int32 or int64 format",
                            format!("swagger path:{path} schema:{schema:?}"),
                        ));
                    };
                }
            } else if format_value.eq("float") || format_value.eq("double") {
                //check if the float or double format has a number type
                if let Some(schema_type) = schema.inner(&self.swagger_value).schema_type {
                    if schema_type.as_str().to_lowercase() != "number" {
                        let _ = &alerts.push(Alert::new(
                            Level::Info,
                            "Type number must have a float or double format",
                            format!("swagger path:{path} schema:{schema:?}"),
                        ));
                    }
                }
            }
        }
    }

    pub fn check_int_type(&self) -> Vec<Alert> {
        // this function check  the get paramter schema all component and response and request body that does not use component
        // The purpose of the check is to ensure that the type number correspond to integer format and type number has a float format
        let mut hashset_compo_name: HashSet<String> = HashSet::new();

        let mut alerts: Vec<Alert> = vec![];
        let schemas = &self
            .swagger
            .components()
            .unwrap_or_default()
            .schemas
            .unwrap_or_default();
        for (key, value) in schemas {
            //dive into schema
            let _name = format!("#/components/schemas/{key}"); // building the whole components value
            hashset_compo_name.insert(key.to_string()); // insert the key of the schema into hashset
            if let Some(propert) = value.inner(&self.swagger_value).properties {
                //if there is properties
                for (key, schemaref) in propert {
                    if let Some(format_value) = schemaref.inner(&self.swagger_value).format {
                        if format_value.eq("int32") || format_value.eq("int64") {
                            // check if the format is int32 or int64
                            if let Some(schema_type) =
                                schemaref.inner(&self.swagger_value).schema_type
                            {
                                if schema_type.as_str().to_lowercase() != "integer" {
                                    // int32 or int 64 has to be "integer" as type so the alert is raised
                                    alerts.push(Alert::new(
                                        Level::Info,
                                        "Type integer must have a int32 or int64 format",
                                        format!("component name: {key}"),
                                    ));
                                };
                            }
                        } else if format_value.eq("float") || format_value.eq("double") {
                            //check if the float or double format has a number type
                            if let Some(schema_type) =
                                schemaref.inner(&self.swagger_value).schema_type
                            {
                                if schema_type.as_str().to_lowercase() != "number" {
                                    let _ = &alerts.push(Alert::new(
                                        Level::Info,
                                        "Type number must have a float or double format",
                                        format!("component name: {key:?}"),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        for (path, item) in &self.swagger.get_paths() {
            // dive into all path from the OAS file
            for (_m, op) in item.get_ops() {
                for i in op.params() {
                    // dive into schema of GET requests which is implemented into operation section
                    //schema get parameter

                    let o = i.inner(&self.swagger_value).schema.unwrap();
                    let p = match o {
                        SchemaRef::Ref(value_ref) => value_ref.param_ref.to_string(),
                        SchemaRef::Schema(_v) => "None".to_string(),
                    };
                    if !hashset_compo_name.contains(&p) {
                        // check if we not already check it in the previous loop
                        //if op param and not reference to component

                        if let Some(schema) = i.inner(&self.swagger_value).schema {
                            self.check_schema(schema, &mut alerts, path.clone());
                            //send the schema to the check schema function
                        }
                    }
                }

                for (_key, value) in op.responses() {
                    //dive into the schema responses
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
                            }
                        }
                    }
                }

                if let Some(request_body) = op.request_body.as_ref() {
                    // check schema in the request body
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
                                format!("swagger path:{path} operation:{m} status:{status}"),
                            ));
                        }
                    } else if status != "default" {
                        alerts.push(Alert::new(
                            Level::Low,
                            "Responses have an invalid or unrecognized status code",
                            format!("swagger path:{path} operation:{m} status:{status}"),
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
                                format!("swagger path:{path} method:GET"),
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
                                format!("swagger path:{path} method:PUT"),
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
                                format!("swagger path:{path} method:POST"),
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
                    format!("swagger path:{path} "),
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
                                    format!("swagger path:{path} content type:{c_t}"),
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
                        format!("swagger path:{path} operation:{m}"),
                    ));
                } else if op.description.as_ref().unwrap().is_empty() {
                    alerts.push(Alert::new(
                        Level::Low,
                        "Operation has an empty description",
                        format!("swagger path:{path} operation:{m}"),
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
                        format!("swagger path:{path} operation:{m}"),
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
