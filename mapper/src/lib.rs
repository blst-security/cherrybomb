use digest::*;
use std::collections::{HashMap, HashSet};
use uuid::{Uuid, Version};
pub fn fingerprint_string(strings: Vec<&String>) -> StringDescriptor {
    let desc = if let Ok(u) = Uuid::parse_str(strings[0]) {
        match u.get_version() {
            Some(Version::Nil) => StringDescriptor::Uuid(0),
            Some(Version::Mac) => StringDescriptor::Uuid(1),
            Some(Version::Dce) => StringDescriptor::Uuid(2),
            Some(Version::Md5) => StringDescriptor::Uuid(3),
            Some(Version::Random) => StringDescriptor::Uuid(4),
            Some(Version::Sha1) => StringDescriptor::Uuid(5),
            None => StringDescriptor::Uuid(255),
        }
    } else {
        let mut fp_hash = HashSet::new();
        for string in strings {
            fp_hash.insert(string.to_string());
            if fp_hash.len() > 100 {
                return StringDescriptor::Random;
            }
        }
        StringDescriptor::List(fp_hash.into_iter().collect())
    };
    desc
}
pub fn fingerprint_number(numbers: Vec<&String>) -> ValueDescriptor {
    let mut fp_hash = HashSet::new();
    let mut nt = NumType::Integer;
    let mut lowest = 0f64;
    let mut highest = 0f64;
    for number in numbers {
        if let Ok(num) = number.parse::<f64>() {
            fp_hash.insert(num as i64);
            if num.trunc() != num {
                nt = NumType::Float;
            }
            if num < lowest {
                lowest = num;
            } else if num > highest {
                highest = num;
            }
        } else {
            return ValueDescriptor::Unknown;
        }
    }
    if fp_hash.len() < 100 {
        ValueDescriptor::Number((NumDescriptor::List(fp_hash.into_iter().collect()), nt))
    } else {
        ValueDescriptor::Number((NumDescriptor::Range((lowest as i64, highest as i64)), nt))
    }
}
pub fn search_for_patterns(values: Vec<&String>) -> ValueDescriptor {
    let pointers = values.iter().take(10);
    let mut weights = (0u16, 0u16, 0u16);
    for pointer in pointers.clone().into_iter() {
        if let Ok(_) = pointer.parse::<f64>() {
            weights.0 += 1;
        } else if let Ok(_) = pointer.parse::<bool>() {
            weights.1 += 1;
        } else {
            weights.2 += 1;
        }
    }
    let len1 = pointers.clone().len() as u16;
    match (
        weights.0 * 100 / len1 > 75,
        weights.1 * 100 / len1 > 75,
        weights.2 * 100 / len1 > 75,
    ) {
        (true, ..) => fingerprint_number(values),
        (false, true, false) => ValueDescriptor::Bool,
        (.., true) => ValueDescriptor::String(fingerprint_string(values)),
        (false, false, false) => ValueDescriptor::default(),
    }
}
pub fn check_values_req(values: &HashSet<String>) -> ValueDescriptor {
    search_for_patterns(values.into_iter().collect())
}
pub fn check_values_res(values: &HashMap<String, u32>) -> ValueDescriptor {
    let mut split = Split::<String>::from_hashmap(values);
    split.filter();
    search_for_patterns(split.values.iter().collect())
}
trait MapDigest {
    fn create_map(&mut self);
    fn turn_hash(&self) -> Vec<Endpoint>;
}
impl MapDigest for Digest {
    fn turn_hash(&self) -> Vec<Endpoint> {
        let ep_hashes = &self.ep_hash;
        let mut eps = vec![];
        for ep_hash in ep_hashes {
            eps.push(Endpoint::from_hash(ep_hash))
        }
        eps
    }
    fn create_map(&mut self) {
        let links_hash = &self.link_hash;
        let mut groups: Vec<Group> = vec![];
        let mut links = vec![];
        let mut endpoints = HashSet::new();
        for ep_s in links_hash.keys() {
            let total: u64 = links_hash.get(&ep_s).unwrap().values().sum();
            for (ep_t, amount) in links_hash.get(&ep_s).unwrap().iter() {
                if total / amount <= 10 {
                    links.push(GroupLink {
                        from: ep_s.clone(),
                        to: ep_t.clone(),
                        strength: *amount,
                    });
                    endpoints.insert(ep_s.clone());
                    endpoints.insert(ep_t.clone());
                }
            }
        }
        self.eps = endpoints.iter().map(|e| e.clone()).collect();
        while !links.is_empty() {
            let mut links_new = vec![];
            let mut group = Group::default();
            for i in 0..links.len() {
                if i > 0 && group.endpoints.contains(&links[0].from) {
                    group.links.push(links[i].clone());
                    group.endpoints.push(links[i].to.clone());
                } else if i == 0 {
                    group.links.push(links[0].clone());
                    group.endpoints.push(links[0].from.clone());
                    group.endpoints.push(links[0].to.clone());
                } else {
                    links_new.push(links[i].clone());
                }
            }
            groups.push(group);
            links = links_new;
        }
        self.groups = groups;
    }
}
trait MapEp {
    fn from_hash(ep_hash: &EndpointHash) -> Endpoint;
    fn get_headers(headers: &HashMap<String, HashMap<String, u32>>) -> Vec<Header>;
    fn get_req_res_payloads(hash: &EndpointHash) -> RRPayload;
}

impl MapEp for Endpoint {
    fn get_headers(headers: &HashMap<String, HashMap<String, u32>>) -> Vec<Header> {
        //let mut total:u64 = 0;
        let mut req_headers = vec![];
        for header in headers.keys() {
            //total+= headers.get(header).unwrap().values().sum();
            let mut g = 0;
            let mut v = String::new();
            for (val, amount) in headers.get(header).unwrap().iter() {
                if *amount > g {
                    g = *amount;
                    v = val.clone();
                }
            }
            req_headers.push(Header {
                name: header.clone(),
                value: v,
            });
        }
        req_headers
    }
    fn get_req_res_payloads(hash: &EndpointHash) -> RRPayload {
        let mut req_payload_params = vec![];
        for (param, payloads) in hash.queries.reqp_map.iter() {
            let value = check_values_req(payloads);
            req_payload_params.push(ParamDescriptor {
                from: QuePay::Query,
                name: param.to_string(),
                value,
            });
        }
        for (param, payloads) in hash.status_payloads.reqp_map.iter() {
            let value = check_values_req(payloads);
            req_payload_params.push(ParamDescriptor {
                from: QuePay::Payload,
                name: param.to_string(),
                value,
            });
        }
        let req_payload = PayloadDescriptor {
            params: req_payload_params,
        };

        let mut res_payload_params = vec![];
        let mut statuses = hash.queries.status_map.clone();
        for (param, payloads) in hash.queries.resp_map.iter() {
            let value = check_values_res(payloads);
            res_payload_params.push(ParamDescriptor {
                from: QuePay::Response,
                name: param.to_string(),
                value,
            });
        }
        statuses.extend(&hash.status_payloads.status_map);
        for (param, payloads) in hash.status_payloads.resp_map.iter() {
            let value = check_values_res(payloads);
            res_payload_params.push(ParamDescriptor {
                from: QuePay::Response,
                name: param.to_string(),
                value,
            });
        }
        let res_payload = PayloadDescriptor {
            params: res_payload_params,
        };
        RRPayload {
            status: Split::from_hashmap(&statuses),
            req_payload,
            res_payload,
        }
    }
    fn from_hash(ep_hash: &EndpointHash) -> Endpoint {
        let common_req_headers = HeaderMap::new(Self::get_headers(&ep_hash.req_headers));
        let common_res_headers = HeaderMap::new(Self::get_headers(&ep_hash.res_headers));
        Endpoint {
            common_req_headers,
            common_res_headers,
            path: ep_hash.path.clone(),
            methods: Split::from_hashmap(&ep_hash.methods),
            payload_delivery_methods: Split::from_hashmap(&ep_hash.dm),
            req_res_payloads: Self::get_req_res_payloads(&ep_hash),
        }
    }
}
pub trait MapLoad {
    fn load_session(&mut self, _session: Session);
    fn load_vec_session(&mut self, _sessions: Vec<Session>);
    fn load_req_res(&mut self, _req_res: ReqRes);
    fn load_vec_req_res(&mut self, _req_reses: Vec<ReqRes>);
}
impl MapLoad for Digest {
    fn load_session(&mut self, session: Session) {
        for i in 0..(session.req_res.len() - 1) {
            let mut found = false;
            for ep_hash in &mut self.ep_hash {
                if ep_hash.path == session.req_res[i].path {
                    ep_hash.load(&session.req_res[i]);
                    found = true;
                }
            }
            if !found {
                self.ep_hash
                    .push(EndpointHash::new(session.req_res[i].path.clone()));
            }
        }
        let eps = self.turn_hash();
        let mut links = vec![];
        for i in 0..(session.req_res.len() - 1) {
            //should be one!!!
            let index = eps
                .iter()
                .position(|ep| ep.path == session.req_res[i].path)
                .unwrap();
            let from = eps[index].clone();
            for j in (i + 1)..(session.req_res.len() - 1) {
                let index = eps
                    .iter()
                    .position(|ep| ep.path == session.req_res[j].path)
                    .unwrap();
                let to = eps[index].clone();
                links.push(Link {
                    from: from.clone(),
                    to,
                });
            }
        }
        self.link_hash.load_data(links);
        self.create_map();
    }
    fn load_vec_session(&mut self, sessions: Vec<Session>) {
        for session in sessions.iter() {
            for i in 0..(session.req_res.len() - 1) {
                let mut found = false;
                for ep_hash in &mut self.ep_hash {
                    if ep_hash.path == session.req_res[i].path {
                        ep_hash.load(&session.req_res[i]);
                        found = true;
                    }
                }
                if !found {
                    self.ep_hash
                        .push(EndpointHash::new(session.req_res[i].path.clone()));
                }
            }
        }
        let eps = self.turn_hash();
        let eps_path: Vec<String> = eps.iter().map(|e| e.path.clone()).collect();
        let mut links = vec![];
        for session in sessions {
            for i in 0..(session.req_res.len() - 1) {
                for j in 0..(eps.len() - 1) {
                    if session.req_res[i].path == eps_path[j] {
                        links.push(Link {
                            from: eps[j].clone(),
                            to: eps[j + 1].clone(),
                        });
                    }
                }
            }
        }
        self.link_hash.load_data(links);
        self.create_map();
    }
    fn load_req_res(&mut self, _req_res: ReqRes) {}
    fn load_vec_req_res(&mut self, _req_reses: Vec<ReqRes>) {}
}
