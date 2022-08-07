use super::*;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub fn not_2xx(check_ret: CheckRetVal) -> (Vec<Alert>, AttackLog) {
        //todo prob should change name
        let mut ret_val = vec![];
        for (res_data, response) in check_ret.0.into_iter() {
            if (200..300u16).contains(&response.status) {
                ret_val.push(Alert::with_certainty(
                    Level::Low,
                    res_data.alert_text,
                    res_data.location,
                    Certainty::Certain,
                ))
            }
        }
        (ret_val, check_ret.1)
    }

    pub fn check_if_3xx(check_ret: CheckRetVal) -> (Vec<Alert>, AttackLog) {
        let mut ret_val = vec![];
        for (res_data, response) in check_ret.0.into_iter() {
            if (300..300u16).contains(&response.status) {
                ret_val.push(Alert::with_certainty(
                    Level::Medium,
                    res_data.alert_text,
                    res_data.location,
                    Certainty::Certain,
                ))
            }
        }
        (ret_val, check_ret.1)
    }

    pub fn reflected_and_2xx(
        check_ret_param: (CheckRetVal, Vec<String>),
    ) -> (Vec<Alert>, AttackLog) {
        let mut ret_val = vec![];
        let check_ret_only = check_ret_param.0;
        let check_ret = check_ret_only.0;
        for (res_data, response) in &check_ret {
            for polluted in &check_ret_param.1 {
                if (200..300u16).contains(&response.status) && response.payload.contains(polluted) {
                    ret_val.push(Alert::with_certainty(
                        Level::Medium,
                        res_data.alert_text.to_string(),
                        res_data.location.to_string(),
                        Certainty::Certain,
                    ))
                }
            }
        }
        (ret_val, check_ret_only.1)
    }
}
