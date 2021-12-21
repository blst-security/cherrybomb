use super::*;
use anomaly_scores::*;
use std::collections::HashMap;

fn test_single<T>(cur: &T, other: &Split<T>) -> u16
where
    T: Clone + Eq + PartialEq + Default + std::hash::Hash,
{
    if let Some(p) = other.get(cur) {
        match p {
            0 => BOTTOM_PRECENTILE_SCORE,
            1..=2 => LOW_PRECENTILE_SCORE,
            3..=7 => MID_PRECENTILE_SCORE,
            8..=15 => HIGH_PRECENTILE_SCORE,
            16..=100 => TOP_PRECENTILE_SCORE,
            _ => NONE_PRECENTILE_SCORE,
        }
    } else {
        NONE_PRECENTILE_SCORE
    }
}
fn test_headers(cur: &HashMap<String, String>, other: &HeaderMap) -> u16 {
    let mut a_s = 0;
    //let header_names:Vec<&String> = other.headers.iter().map(|h|&h.name).collect();
    for header in cur.keys() {
        if !other.headers.iter().map(|h| &h.name).any(|x| x == header) {
            a_s += MISSING_HEADER_SCORE;
        }
    }
    a_s
}
/// compairs the payload parameters to the existing map by parameter type and its description
fn test_payload(cur: &str, other: &PayloadDescriptor) -> u16 {
    let params = conv_json_pairs(cur);
    let mut anomaly_score = 0;
    for param in params {
        if let Some(index) = other
            .params
            .iter()
            .position(|p| p.name.trim() == param.param.trim())
        {
            let v_desc = &other.params[index].value;
            match v_desc {
                // checks if the number type matches the mapped type
                // if it does, checks if the payload could be from the type descriptor
                ValueDescriptor::Number((desc, t)) => {
                    if let Ok(n) = param.payload.parse::<f64>() {
                        if n.trunc() != n && t == &NumType::Integer {
                            anomaly_score += NUM_TYPE_MISMATCH_SCORE;
                        } else if !desc.matches(n as i64) {
                            anomaly_score += DESCRIPTOR_MISMATCH_SCORE;
                        }
                    } else {
                        anomaly_score += PARAM_TYPE_MISMATCH_SCORE;
                    }
                }
                // checks if the payload could be from the type descriptor
                ValueDescriptor::String(desc) => {
                    if !desc.matches(&param.payload) {
                        anomaly_score += DESCRIPTOR_MISMATCH_SCORE;
                    }
                }
                // checks if its a boolean
                ValueDescriptor::Bool => {
                    if param.payload.parse::<bool>().is_err() {
                        anomaly_score += PARAM_TYPE_MISMATCH_SCORE;
                    }
                }
                _ => (),
            }
        } else {
            anomaly_score += MISSING_PARAM_SCORE;
        }
    }
    anomaly_score
}
pub fn _decide_flow_rule_based(
    _digest: Digest,
    _session: Session,
    _top_anomaly_score: u16,
) -> (bool, Option<ReqRes>) {
    (false, None)
}
pub fn decide_rule_based(
    digest: &Digest,
    session: &Session,
    top_anomaly_score: u16,
) -> (bool, Option<ReqRes>, Vec<u16>) {
    /*
    if let Some(group) = detect_group(&session,&digest){
        let g_eps_path:Vec<String> = group.endpoints.iter().map(|e| e.path).collect();
        for req_res in session{
            let i = match g_eps_path.position(|&p| p==req_res.path)
            if req_res.
        }
    }else{
        true
    }*/
    let eps_path: Vec<&String> = digest.eps.iter().map(|e| &e.path.path_ext).collect();
    let mut total_anomaly_score = 0;
    let mut anomaly_scores = vec![];
    let mut cond1 = false;
    let mut ep_true = None;
    for ep in session.req_res.clone() {
        let mut anomaly_score = 0;
        if let Some(i) = eps_path.iter().position(|p| p == &(&ep.path)) {
            let ep_digest = &digest.eps[i];
            if ep.status != 404 {
                anomaly_score += test_single(&ep.method, &ep_digest.methods);
                anomaly_score += test_single(&ep.status, &ep_digest.req_res_payloads.status);
                anomaly_score += test_headers(&ep.res_headers, &ep_digest.common_res_headers);
                anomaly_score +=
                    test_payload(&ep.res_payload, &ep_digest.req_res_payloads.res_payload);
            } else {
                anomaly_score += ERR_404_SCORE;
            }
        }
        if anomaly_score >= (TOP_ENDPOINT_ANOMALY_SCORE) && !cond1 {
            cond1 = true;
            ep_true = Some(ep);
        }
        total_anomaly_score += anomaly_score;
        anomaly_scores.push(anomaly_score);
    }
    (
        total_anomaly_score > top_anomaly_score || cond1,
        ep_true,
        anomaly_scores,
    )
}
