use super::*;
use crate::scan::active::*;
use crate::scan::passive::*;
use comfy_table::*;
use strum_macros::EnumIter;

///Add the rule name to this enum
impl Default for PassiveChecks {
    fn default() -> Self {
        //Self::No404
        Self::CheckServerUrl(vec![])
    }
}
pub trait Check {
    fn alerts_text(&self) -> Cell;
    fn top_severity(&self) -> Level;
    fn result(&self) -> &'static str;
}
impl Check for PassiveChecks {
    fn alerts_text(&self) -> Cell {
        match self.inner().len() {
            0 => Cell::new(self.inner().len())
                .fg(Color::Green)
                .add_attribute(Attribute::Bold),
            1..=10 => Cell::new(self.inner().len())
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold),
            11..=99 => Cell::new(self.inner().len())
                .fg(Color::Red)
                .add_attribute(Attribute::Bold),
            _ => Cell::new(self.inner().len())
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
                .add_attribute(Attribute::SlowBlink),
        }
    }
    fn top_severity(&self) -> Level {
        let mut top = Level::Info;
        for alert in self.inner() {
            if alert.level > top {
                top = alert.level;
            }
        }
        top
    }
    fn result(&self) -> &'static str {
        //let failed = self.inner().iter().map(|a| if a.level != Level::Info {1}else{0}).sum::<u64>();
        if self.inner().is_empty() {
            "PASSED"
        } else {
            "FAILED"
        }
    }
}

impl Check for ActiveChecks {
    fn alerts_text(&self) -> Cell {
        match self.inner().len() {
            0 => Cell::new(self.inner().len())
                .fg(Color::Green)
                .add_attribute(Attribute::Bold),
            1..=10 => Cell::new(self.inner().len())
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold),
            11..=99 => Cell::new(self.inner().len())
                .fg(Color::Red)
                .add_attribute(Attribute::Bold),
            _ => Cell::new(self.inner().len())
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
                .add_attribute(Attribute::SlowBlink),
        }
    }
    fn top_severity(&self) -> Level {
        let mut top = Level::Info;
        for alert in self.inner() {
            if alert.level > top {
                top = alert.level;
            }
        }
        top
    }
    fn result(&self) -> &'static str {
        if !self.inner().is_empty() {
            "FAILED"
        } else {
            "PASSED"
        }
    }
}

impl_passive_checks![
    //name in enum   check function   check name    check description
    (CheckServerUrl,check_server_url,"SERVER URL","Checks for server url misconfigurations"),
    (CheckAdditionalProperties,check_additional_properties,"ADDITIONAL PROPERTIES","Checks for bad defaults in object additional properties, alerts if the swagger is using the default configuration"),
    (CheckDefaultResponse,check_default_response,"DEFAULT RESPONSE","Checks for the definition of a default response, and alerts if none is defined"),
    (CheckResponseBodySchema,check_response_body_schema,"RESPONSE BODY SCHEMA","Checks the response body schema, and alerts when there is none"),
    (CheckDefaultType,check_default_type,"DEFAULT TYPE","Checks that the default type is the same as the parameter type"),
    (CheckEnumType,check_enum_type,"ENUM TYPE","Checks that the Enum type is the same as the parameter type"),
    //(CheckRequiredUndefined,check_required_undefined,"REQUIRED UNDEFINED","Checks for any required parameters that are undefined"),
    (CheckUnusedSchema,check_unused_schema,"UNUSED SCHEMA","Checks for unused schemas"),
    (Check401,check_401,"401","Checks for a 401 response if there is authentication necessary"),
    (Check403,check_403,"403","Checks for a 403 response if there is authentication necessary"),
    (CheckSuccesses,check_successes,"RESPONSE SUCCESSES (2xx)","Checks for successful responses (2xx) in every operation"),
    (CheckAuth,check_auth,"AUTH","Checks for a global authentication definition"),
    (CheckFNAuth,check_fn_auth,"ENDPOINT AUTH","Checks for an authentication definition for each endpoint"),
    (CheckIntAttrs,check_int_attrs,"INTEGER ATTRIBUTES","Checks for the definition of integer type attributes - maximum, minimum"),
    (CheckStrAttrs,check_str_attrs,"STRING ATTRIBUTES","Checks for the definition of string type attributes - max_length, min_length, pattern"),
    (CheckArrAttrs,check_arr_attrs,"ARRAY ATTRIBUTES","Checks for the definition of array type attributes - max_items, min_items"),
    (CheckObjAttrs,check_obj_attrs,"OBJECT ATTRIBUTES","Checks for the definition of object type attributes - max_properties, properties"),
    (CheckValidResponses,check_valid_responses,"VALID RESPONSES","Checks for valid responses codes"),
    (CheckMethodPermissions, check_method_permissions, "METHOD PERMISSIONS", "Checks for correct permission configuration for GET/PUT/POST requests"),
    (CheckContainsOperation, check_contains_operation, "CONTAINS OPERATION", "Checks that each path contains at least one operation"),
    (CheckValidEncodings, check_valid_encoding, "VALID ENCODINGS", "Checks that all content types are valid"),
    (CheckDescription, check_description, "DESCRIPTION", "Checks that all operations have a description"),
    (CheckContainsResponse, check_contains_response, "CONTAINS RESPONSE", "Checks that each operation has a response")
];

impl_active_checks![(
    CheckMethodEncoding,
    check_method_encoding,
    is_2xx,
    "Check Content-type header",
    "Check if the endpoint can be send with other content type"
)];
