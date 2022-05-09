use super::*;
use serde_json::json;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self,auth:&Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut logs = AttackLog::default();
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            for url in urls {

                let req = AttackRequest::builder()
                    .uri(&url.1,&path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(auth.clone())
                    .build();
                if let Ok(res) = req.send_request(true).await{
                    logs.requests.push(req);
                    logs.responses.push(res);
                }else{
                    println!("oopsie poopsie request failed");
                }
        alerts.push(Alert::with_certainty(Level::Low,"description","https://thingy".to_string(),Certainty::Certain));
            }
        }
        //println!("{:?}",logs);
        alerts
    }

    pub async fn check_raz(&self,auth:&Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let mut logs = AttackLog::default();
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            for (m,op) in item.get_ops(){
                if let Some(r_body) = &op.request_body {
                    let json = json!({
                            });
                    let r_body = r_body.inner(&self.oas_value);
                    for (name, m_t) in r_body.content {
                        if let Some(s) = m_t.schema {
                            let s = s.inner(&self.oas_value);
                            println!("{:?}",s);
                        }
                    }
                }
            } //todo remove

            let t = &self.oas_value;
            for url in urls {
                let req = AttackRequest::builder()
                    .uri(&url.1,&path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(auth.clone())
                    .build();
                if let Ok(res) = req.send_request(true).await{
                    logs.requests.push(req);
                    logs.responses.push(res);
                }else{
                    println!("oopsie poopsie request failed");
                }
                alerts.push(Alert::with_certainty(Level::Low,"description","https://thingy".to_string(),Certainty::Certain));
            }
        }
        //println!("{:?}",logs);
        alerts
    }
}


