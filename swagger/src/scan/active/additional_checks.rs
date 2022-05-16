use super::*;
use serde_json::json;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self, auth: &Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut logs = AttackLog::default();
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            for url in urls {
                let req = AttackRequest::builder()
                    .uri(&url.1, &path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(auth.clone())
                    .build();
                if let Ok(res) = req.send_request(true).await {
                    logs.requests.push(req);
                    logs.responses.push(res);
                } else {
                    println!("oopsie poopsie request failed");
                }
                alerts.push(Alert::with_certainty(Level::Low, "description", "https://thingy".to_string(), Certainty::Certain));
            }
        }
        //println!("{:?}",logs);
        alerts
    }

    pub async fn check_raz(&self, auth: &Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut logs = AttackLog::default();
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            for (m, op) in item.get_ops() {
                if let Some(r_body) = &op.request_body {
                    let r_body = r_body.inner(&self.oas_value);
                    for (name, m_t) in r_body.content {
                        let mut json = json! {null};
                        // json[get_name_s_ref()] = serde_json::Value::String("string".to_string());
                        println!("{:?}", json);
                        if let Some(s) = m_t.schema {
                            let req_body = create_test_body(None, m_t);
                            let s = s.inner(&self.oas_value);
                            for (name, prop) in s.properties.unwrap_or_default() {
                                let true_name = get_name_s_ref(&prop, &self.oas_value, &Some(name));
                                // let val =
                            }
                            //println!("{:?}",s);
                        }
                    }
                }
            } //todo remove

            let t = &self.oas_value;
            for url in urls {
                let req = AttackRequest::builder()
                    .uri(&url.1, &path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(auth.clone())
                    .build();
                if let Ok(res) = req.send_request(true).await {
                    logs.requests.push(req);
                    logs.responses.push(res);
                } else {
                    println!("oopsie poopsie request failed");
                }
                alerts.push(Alert::with_certainty(Level::Low, "description", "https://thingy".to_string(), Certainty::Certain));
            }
        }
        //println!("{:?}",logs);
        alerts
    }
}


fn get_name_s_ref(s_ref: &SchemaRef, value: &Value, name: &Option<String>) -> String {
    let schema = s_ref.inner(value);
    if let Some(ref t) = schema.title {
        t.to_string()
    } else if let SchemaRef::Ref(r) = s_ref {
        r.param_ref.split('/').last().unwrap().to_string()
    } else if let Some(n) = name {
        n.to_string()
    } else {
        String::new()
    }
}

fn create_test_body(obj: Option<serde_json::Value>, mt: MediaType) -> serde_json::Value {
    if obj.is_some() {

    }
    println!("test");
    json!(null)
}