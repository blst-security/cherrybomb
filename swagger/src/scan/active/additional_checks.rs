use super::*;
use serde_json::json;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self, auth: &Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut logs = AttackLog::default();
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            for url in urls {
                // println!("PAYLOAD: {}",build_payload(&item, &self.oas_value).to_string());
                let req = AttackRequest::builder()
                    .uri(&url.1, &path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(auth.clone())
                    .payload(&build_payload(&item,&self.oas_value).to_string())
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
        }
        alerts
    }
}

fn build_payload(path: &PathItem, oas: &Value) -> Value {
    let mut ret = json!({});
    let (_, op) = path.get_ops()[0];
    if let Some(req) = &op.request_body {
        for (_, med_t) in req.inner(oas).content {
            if let Some(s_ref) = &med_t.schema {
                ret  = unwind_scheme(s_ref,oas);
            }
        }
    }
    ret
}


fn unwind_scheme(reference: &SchemaRef, oas: &Value ) -> Value{
    let mut payload = json!({});
    // println!("{:?}",reference.inner(oas));
    let reference = reference.inner(oas);
    if let Some(example) = reference.example{
        return example;
    }
    if let Some(prop_map) =  reference.properties {
        for (name,schema) in prop_map{
            payload[name] = match schema {
                SchemaRef::Ref(_) => {
                    unwind_scheme(&schema, &oas)
                }
                SchemaRef::Schema(schema) => {
                     if let Some(example) = schema.example {
                         example
                    }
                    else{
                        json!({})
                    }
                }

            };
        }
    }
    else if let Some(item_map) = reference.items {
        return unwind_scheme(item_map.as_ref(),oas);
    }
    payload
}