use crate::scan::passive::passive_scanner::*;
use crate::scan::passive::utils::*;
use crate::scan::*;
use cherrybomb_oas::legacy::legacy_oas::OAS;

pub trait PassiveTypeScan {
    fn check_int_attrs(&self) -> Vec<Alert>;
    fn check_str_attrs(&self) -> Vec<Alert>;
    fn check_arr_attrs(&self) -> Vec<Alert>;
    fn check_obj_attrs(&self) -> Vec<Alert>;
}
impl<T: OAS + Serialize> PassiveTypeScan for PassiveSwaggerScan<T> {
    fn check_int_attrs(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let schemas = get_schemas_by_type(&self.swagger, &self.swagger_value, "integer");
        for (schema, location) in schemas {
            if schema.minimum.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Number schema without a minimum",
                    location.clone(),
                ));
            }
            if schema.maximum.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Number schema without a maximum",
                    location,
                ));
            }
        }
        let schemas = get_schemas_by_type(&self.swagger, &self.swagger_value, "number");
        for (schema, location) in schemas {
            if schema.minimum.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Number schema without a minimum",
                    location.clone(),
                ));
            }
            if schema.maximum.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Number schema without a maximum",
                    location,
                ));
            }
        }
        alerts
    }
    fn check_str_attrs(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let schemas = get_schemas_by_type(&self.swagger, &self.swagger_value, "string");
        for (schema, location) in schemas {
            if schema.min_length.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "String schema without a minimum length",
                    location.clone(),
                ));
            }
            if schema.max_length.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "String schema without a maximum length",
                    location.clone(),
                ));
            }
            if schema.pattern.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "String schema without a pattern",
                    location,
                ));
            }
        }
        alerts
    }
    fn check_arr_attrs(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let schemas = get_schemas_by_type(&self.swagger, &self.swagger_value, "array");
        for (schema, location) in schemas {
            if schema.min_items.is_none() {
                alerts.push(Alert::new(
                    Level::Info,
                    "Array schema without an item minimum",
                    location.clone(),
                ));
            }
            if schema.max_items.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Array schema without an item maximum",
                    location,
                ));
            }
        }
        alerts
    }
    fn check_obj_attrs(&self) -> Vec<Alert> {
        let mut alerts = vec![];
        let schemas = get_schemas_by_type(&self.swagger, &self.swagger_value, "object");
        for (schema, location) in schemas {
            if schema.min_properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without minimum properties",
                    location.clone(),
                ));
            }
            if schema.max_properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without maximum properties",
                    location.clone(),
                ));
            }
            if schema.properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without properties",
                    location.clone(),
                ));
            } else if schema.properties.unwrap().is_empty() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without properties",
                    location,
                ));
            }
        }
        let schemas = get_schemas_by_type(&self.swagger, &self.swagger_value, "");
        for (schema, location) in schemas {
            if schema.min_properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without minimum properties",
                    location.clone(),
                ));
            }
            if schema.max_properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without maximum properties",
                    location.clone(),
                ));
            }
            if schema.properties.is_none() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without properties",
                    location.clone(),
                ));
            } else if schema.properties.unwrap().is_empty() {
                alerts.push(Alert::new(
                    Level::Low,
                    "Object schema without properties",
                    location,
                ));
            }
        }
        alerts
    }
}
