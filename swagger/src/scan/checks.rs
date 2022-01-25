use super::*;
use strum_macros::EnumIter;
use crate::scan::passive::*;

///Add the rule name to this enum
impl Default for PassiveChecks{
    fn default()->Self{
        //Self::No404
        Self::CheckServerUrl(vec![])
    }
}
impl PassiveChecks{
    pub fn alerts_text(&self)->ColoredString{
        match self.inner().len(){
            0=>"0".green().bold(),
            1..=10=>self.inner().len().to_string().yellow().bold(),
            11..=99=>self.inner().len().to_string().red().bold(),
            _=>self.inner().len().to_string().red().bold().blink(),
        }
    }
    pub fn result(&self)->&'static str{
        if self.inner().len()>0{
            "FAILED"
        }else{
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
    (CheckRequiredUndefined,check_required_undefined,"REQUIRED UNDEFINED","Checks for any required parameters that are undefined"),
    (CheckUnusedSchema,check_unused_schema,"UNUSED SCHEMA","Checks for unused schemas"),
    (Check401,check_401,"401","Checks for a 401 response if there is authentication necessary"),
    (Check403,check_403,"403","Checks for a 403 response if there is authentication necessary"),
    (CheckSuccesses,check_successes,"RESPONSE SUCCESSES (2xx)","Checks for successful responses (2xx) in every operation"),
    (CheckAuth,check_auth,"AUTH","Checks for a global authentication definition"),
    (CheckFNAuth,check_fn_auth,"ENDPOINT AUTH","Checks for an authentication definition for each endpoint"),
    (CheckIntAttrs,check_int_attrs,"INTEGER ATTRIBUTES","Checks for the definion of integer type attributes - maximum, minimum"),
    (CheckStrAttrs,check_str_attrs,"STRING ATTRIBUTES","Checks for the definion of string type attributes - max_length, min_length, pattern"),
    (CheckArrAttrs,check_arr_attrs,"ARRAY ATTRIBUTES","Checks for the definion of array type attributes - max_items, min_items"),
    (CheckObjAttrs,check_obj_attrs,"OBJECT ATTRIBUTES","Checks for the definion of object type attributes - max_properties, properties"),
    (CheckValidResponses,check_valid_responses,"VALID RESPONSES","Checks for valid responses codes")
];
