use std::iter;
use super::*;
use serde_json::json;
// use std::collections::HashMap;


impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self, auth: &Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut logs = AttackLog::default();
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            let mut map = HashMap::<Vec<String>, Schema>::new();
            for url in urls {
                let req = AttackRequest::builder()
                    .uri(&url.1, &path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(auth.clone())
                    .payload(&build_payload(&item, &self.oas_value, &mut map).to_string())
                    .build();

                if let Ok(res) = req.send_request(true).await {
                    logs.requests.push(req);
                    logs.responses.push(res);
                    // println!("{:?}",logs);
                } else {
                    // println!("request failed");
                }
                alerts.push(Alert::with_certainty(Level::Low, "description", "hi".to_string(), Certainty::Certain));
            }
            dbg!(map);
        }
        alerts
    }
}

fn build_payload(path: &PathItem, oas: &Value, map: &mut HashMap<Vec<String>, Schema>) -> Value {
    let mut ret = json!({});
    let (_, op) = path.get_ops()[0];
    if let Some(req) = &op.request_body {
        for (_, med_t) in req.inner(oas).content {
            if let Some(s_ref) = &med_t.schema {
                ret = unwind_scheme(s_ref, oas, map);
            }
        }
    }
    ret
}

fn unwind_scheme(reference: &SchemaRef, oas: &Value, map: &mut HashMap<Vec<String>, Schema>) -> Value {
    let mut payload = json!({});
    let mut path = Vec::<String>::new();
    let reference = reference.inner(oas);
    if let Some(example) = reference.example {
        return dbg!(example);
    }
    if let Some(prop_map) = reference.properties {
        for (name, schema) in prop_map {
            path.push(name.clone());
            payload[&name] = match schema {
                SchemaRef::Ref(_) => {
                    unwind_scheme(&schema, &oas, map)
                }
                SchemaRef::Schema(schema) => {
                    map.insert(
                        path.clone(),
                        *schema.clone(),
                    );
                    path.pop();
                    if let Some(example) = schema.example {
                        example
                    } else {
                        gen_default_value(schema)
                    }
                }
            };
        }
    } else if let Some(item_map) = reference.items {
        return json!([unwind_scheme(item_map.as_ref(), oas, map)]);
    }
    payload
}

fn gen_default_value(schema: Box<Schema>) -> Value {
    let ret: Value =
        if let Some(data_type) = schema.schema_type {
            match data_type.as_str() {
                "string" => {
                    if let Some(num) = schema.min_length {
                        json!(iter::repeat(['B','L','S','T']).
                            flatten().
                            take(num.try_into().unwrap()).
                            collect::<String>())
                    } else { json!("BLST") }
                }
                "integer" => {
                    if let Some(num) = schema.minimum {
                        json!(num)
                    } else {
                        json!(5)
                    }
                }
                "boolean" => {
                    json!(false)
                }
                _ => {
                    json!({})
                }
            }
        } else {
            json!({})
        };
    ret
}