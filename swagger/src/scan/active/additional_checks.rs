use super::*;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self) -> Vec<Alert> {
        //let mut alerts = vec![];
        //alerts
        for (path, item) in self.oas.get_paths() {
            let urls = get_path_urls(&item, self.oas.servers());
            for url in urls {
                let res = AttackRequest::new()
                    .uri(&url.1,&path)
                    .method(url.0)
                    .headers(vec![])
                    .parameters(vec![])
                    .auth(Authorization::None)
                    .build()
                    .send_request()
                    .await;
            }
        }
        vec![]
    }
}
