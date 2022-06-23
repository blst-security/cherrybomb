use super::*;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub fn not_2xx(&self, responses:Vec<(String, AttackResponse)>) -> Vec<Alert> {
        let mut ret_val = vec![];
        for (description,response) in responses.into_iter(){
            if (200..300u16).contains(&response.status){
                ret_val.push(Alert::with_certainty(Level::Low,
                                                          description,
                                                          "hi".to_string(),
                                                          Certainty::Certain))
            }
        }
        ret_val
    }
}