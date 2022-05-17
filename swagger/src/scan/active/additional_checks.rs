use super::*;



impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_default(&self,auth:&Authorization) -> Vec<Alert> {
        let mut alerts = vec![];
        let  logs = AttackLog::default();
       // let test = self.oas.
        for (path, item) in self.oas.get_paths() {
           println!("{:?} ", item.get_ops()[0].1.parameters);
            let urls = get_path_urls(&item, self.oas.servers());
            for url in urls {
             //   println!(" {:?}",Method::DELETE);
                /*
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
                }*/
        alerts.push(Alert::with_certainty(Level::Low,"description","https://thingy".to_string(),Certainty::Certain));
            }
        }
        //println!("{:?}",logs);
        alerts
    }
}
