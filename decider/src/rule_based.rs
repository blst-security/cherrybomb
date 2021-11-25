use super::*;
use std::collections::HashMap;

fn test_single<T>(cur: &T, other: &Split<T>) -> u16
where
    T: Clone + Eq + PartialEq + Default + std::hash::Hash,
{
    if let Some(p) = other.get(cur) {
        match p {
            0 => 6,
            1..=2 => 5,
            3..=7 => 4,
            8..=15 => 3,
            16..=100 => 0,
            _ => 10,
        }
    } else {
        10
    }
}
fn test_headers(cur: &HashMap<String, String>, other: &HeaderMap) -> u16 {
    let mut a_s = 0;
    let header_names: Vec<&String> = other.headers.iter().map(|h| &h.name).collect();
    for header in cur.keys() {
        if !header_names.contains(&header) {
            a_s += 1;
        }
    }
    a_s
}
fn test_payload(cur: &String, other: &PayloadDescriptor) -> u16 {
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
                ValueDescriptor::Number((desc, t)) => {
                    if let Ok(n) = param.payload.parse::<f64>() {
                        if n.trunc() != n && t == &NumType::Integer {
                            anomaly_score += 15;
                        } else {
                            if !desc.matches(n as i64) {
                                anomaly_score += 10;
                            }
                        }
                    } else {
                        anomaly_score += 20;
                    }
                }
                ValueDescriptor::String(desc) => {
                    if !desc.matches(&param.payload) {
                        anomaly_score += 10;
                    }
                }
                ValueDescriptor::Bool => {
                    if let Err(_) = param.payload.parse::<bool>() {
                        anomaly_score += 20;
                    }
                }
                _ => (),
            }
        } else {
            anomaly_score += 25;
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
    let eps_path: Vec<&String> = digest.eps.iter().map(|e| &e.path).collect();
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
                anomaly_score += 1;
            }
        } 
        if anomaly_score >= (top_anomaly_score / 2) && !cond1 {
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
