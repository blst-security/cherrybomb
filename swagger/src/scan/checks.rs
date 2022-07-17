use super::*;
use crate::scan::active::*;
use crate::scan::passive::*;
use strum_macros::EnumIter;

const LIST_PARAM: [&str; 84] = [
    "page",
    "url",
    "ret",
    "r2",
    "img",
    "u",
    "return",
    "r",
    "URL",
    "next",
    "redirect",
    "redirectBack",
    "AuthState",
    "referer",
    "redir",
    "l",
    "aspxerrorpath",
    "image_path",
    "ActionCodeURL",
    "return_url",
    "link",
    "q",
    "location",
    "ReturnUrl",
    "uri",
    "referrer",
    "returnUrl",
    "forward",
    "file",
    "rb",
    "end_display",
    "urlact",
    "from",
    "goto",
    "path",
    "redirect_url",
    "old",
    "pathlocation",
    "successTarget",
    "returnURL",
    "urlsito",
    "newurl",
    "Url",
    "back",
    "retour",
    "odkazujuca_linka",
    "r_link",
    "cur_url",
    "H_name",
    "ref",
    "topic",
    "resource",
    "returnTo",
    "home",
    "node",
    "sUrl",
    "href",
    "linkurl",
    "returnto",
    "redirecturl",
    "SL",
    "st",
    "errorUrl",
    "media",
    "destination",
    "targeturl",
    "return_to",
    "cancel_url",
    "doc",
    "GO",
    "ReturnTo",
    "anything",
    "FileName",
    "logoutRedirectURL",
    "list",
    "startUrl",
    "service",
    "redirect_to",
    "end_url",
    "_next",
    "noSuchEntryRedirect",
    "context",
    "returnurl",
    "ref_url",
];

///Add the rule name to this enum
impl Default for PassiveChecks {
    fn default() -> Self {
        //Self::No404
        Self::CheckServerUrl(vec![])
    }
}
pub trait Check {
    fn alerts_text(&self) -> ColoredString;
    fn top_severity(&self) -> Level;
    fn result(&self) -> &'static str;
}
impl Check for PassiveChecks {
    fn alerts_text(&self) -> ColoredString {
        match self.inner().len() {
            0 => "0".green().bold(),
            1..=10 => self.inner().len().to_string().yellow().bold(),
            11..=99 => self.inner().len().to_string().red().bold(),
            _ => self.inner().len().to_string().red().bold().blink(),
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
    fn alerts_text(&self) -> ColoredString {
        match self.inner().len() {
            0 => "0".green().bold(),
            1..=10 => self.inner().len().to_string().yellow().bold(),
            11..=99 => self.inner().len().to_string().red().bold(),
            _ => self.inner().len().to_string().red().bold().blink(),
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
    (CheckContainsOperation, check_contains_operation, "CONTAINS OPERATION", "Checks that each path contains at least one operation")
];

impl_active_checks![
    (
        CheckMinMax,
        check_min_max,
        not_2xx,
        "NUMBER LIMITS ENFORCED",
        "checks that the api enforces the number limits in the OAS"
    ),
    (
        CheckStringMaxLength,
        check_string_length_max,
        not_2xx,
        "STRING LEN",
        "check that the api validate the String length"
    ),
    (
        OpenRedirect,
        check_open_redirect,
        check_if_3xx,
        "open redirect",
        "Check if the API may be vulnerable to openredirect"
    ),
    (
        ParameterPollution,
        check_parameter_pollution,
        reflected_and_2xx,
        "parameter pollution",
        "Check if the endpoint is vulnerable to http pollution"
    ),
    (
        CheckSSL,
        check_ssl,
        not_2xx,
        "encrypted communication",
        "Check if the connection is secure"
    ),
    (
        MethodPermissions,
        check_method_permissions,
        not_2xx,
        "Method  permission  ",
        "Check if the endpoint is correctly configured"
    )
];
