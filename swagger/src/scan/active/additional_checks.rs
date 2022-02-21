use super::*;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self,auth:&Authorization) -> Vec<Alert> {
        //let mut alerts = vec![];
        //alerts
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
                    println!("FUCK");
                }
            }
        }
        println!("{:?}",logs);
        vec![]
    }
}
