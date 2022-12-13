use super::utils::create_payload;
///use super::utils::create_payload_for_get;
use super::*;
use reqwest::{self, Url};
use serde::ser::Error;
use serde_json::json;
use utils;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn func_test(&self, _auth: &Authorization) -> CheckRetVal {
        let values_path = self.path_params.clone();
        let ret_val = CheckRetVal::default();
        for (_path, item) in &self.oas.get_paths() {
            for (_m, op) in item.get_ops().iter() {
                self.oas.servers();
                // create_payload(&self.oas_value, op);

                dbg!(create_payload(&self.oas_value, op, &values_path, None));
            }
        }

        ret_val
    }
}
