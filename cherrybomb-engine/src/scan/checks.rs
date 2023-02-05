use super::active::http_client::logs::AttackLog;
use super::passive::passive_scanner::PassiveSwaggerScan;
use super::*;
use crate::active::http_client::auth::Authorization;
use crate::scan::active::active_scanner::ActiveScan;
use crate::scan::passive::auth::*;
use crate::scan::passive::general::*;
use crate::scan::passive::type_checks::*;
use crate::{impl_active_checks, impl_passive_checks};
use cherrybomb_oas::legacy::legacy_oas::OAS;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

///Add the rule name to this enum
impl Default for PassiveChecks {
    fn default() -> Self {
        //Self::No404
        Self::CheckServerUrl(vec![])
    }
}
pub trait Check {
    // fn alerts_text(&self) -> Cell;
    fn top_severity(&self) -> Level;
    fn result(&self) -> &'static str;
}
impl Check for PassiveChecks {
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
    (CheckContainsResponse, check_contains_response, "CONTAINS RESPONSE", "Checks that each operation has a response"),
    (CheckIntegerType, check_int_type, "CHECK FORMAT", "Checks that each integer/number has a correct format")


    ];

impl_active_checks![
    // (
    //     CheckOpenRedirect,
    //     check_open_redirect,
    //     is_3xx,
    //     "OPEN REDIRECT",
    //     "Check if the API may be vulnerable to open redirect"
    // ),
    // (
    //     CheckMinMax,
    //     check_min_max,
    //     is_2xx,
    //     "NUMBER LIMITS ENFORCED",
    //     "checks that the api enforces the number limits in the OAS"
    // ),
    // (
    //     CheckStringMaxLength,
    //     check_string_length_max,
    //     is_2xx,
    //     "STRING LENGTH ENFORCED",
    //     "check that the api validate the String length"
    // ),
    // (
    //     CheckParameterPollution,
    //     check_parameter_pollution,
    //     reflected_and_2xx,
    //     "PARAMETER POLLUTION",
    //     "Check if the endpoint is vulnerable to http pollution"
    // ),
    // (
    //     CheckSSL,
    //     check_ssl,
    //     is_2xx,
    //     "SSL ENFORCED",
    //     "Check if the connection is secure"
    // ),
    // (
    //     CheckMethodPermissionsActive,
    //     check_method_permissions_active,
    //     is_2xx,
    //     "METHOD PERMISSION",
    //     "Check if the endpoint is correctly configured"
    // ),
    // (
    //     CheckAuthenticationPOST,
    //     check_authentication_for_post,
    //     is_2xx,
    //     "AUTH BY PASS",
    //     "Check if the auth is correctly configured"
    // ),
    // (
    //     CheckAuthenticationGET,
    //     check_authentication_for_get,
    //     is_2xx,
    //     "AUTH BY PASS",
    //     "Check if the auth is correctly configured"
    // ),
    // (
    //     CheckSsrfPOST,
    //     check_ssrf_post,
    //     ssrf_and_2xx,
    //     "SSRF POST",
    //     "Check if the endpoint is vulnerable to SSRF"
    // ),
    // (
    //     CheckSsrfGET,
    //     check_for_ssrf,
    //     ssrf_and_2xx,
    //     "SSRF GET",
    //     "Check if the endpoint is vulnerable to SSRF"
    // ),
    // (
    //     CheckBOLA,
    //     check_broken_object_level_authorization,
    //     is_2xx,
    //     "BROKEN OBJECT LEVEL AUTHORIZATION",
    //     "Check if object is vulnerable to level authorization"
    // ),
    // // (
    // //     CheckForSQLInjectionsPOST,
    // //     check_sqli_post,
    // //     reflected_and_2xx,
    // //     "SQL Injection for POST",
    // //     "Check if the endpoint is vulnerable to sql injection"
    // // ),
    // (
    //     CheckForSQLInjections,
    //     check_sqli,
    //     reflected_and_2xx,
    //     "SQL Injection",
    //     "Check if the endpoint is vulnerable to sql injection"
    // ),
    // (
    //     CheckMethodEncoding,
    //     check_method_encoding,
    //     is_2xx,
    //     "Check Content-type header",
    //     "Check if the endpoint can be send with other content type"
    // ),
    (
        CheckIDOR,
        check_broken_object,
        is_2xx,
        "BROKEN OBJECT LEVEL AUTHORIZATION",
        "Check if object is vulnerable to level authorization"
    )
];
