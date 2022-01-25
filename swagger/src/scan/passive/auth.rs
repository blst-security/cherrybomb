use super::*;

pub trait PassiveAuthScan{
    fn check_401(&self)->Vec<Alert>;
    fn check_403(&self)->Vec<Alert>;
    fn check_auth(&self)->Vec<Alert>;
    fn check_fn_auth(&self)->Vec<Alert>;
}
impl PassiveAuthScan for PassiveSwaggerScan{
    ///Rule fucntion
    fn check_401(&self)->Vec<Alert>{
        let mut alerts = vec![];
        for (path,method,p_sec,resps) in get_path_responses(&self.swagger){
            if resps.get("401").is_none() && p_sec.len()>0{
                alerts.push(Alert::new(Level::Low,"Operation has security defined, but no 401 response defined",format!("swagger root path:{} method:{}",path,method)));
            }
        }
        alerts
    }
    fn check_403(&self)->Vec<Alert>{
        let mut alerts = vec![];
        for (path,method,p_sec,resps) in get_path_responses(&self.swagger){
            if resps.get("403").is_none() && p_sec.len()>0{
                alerts.push(Alert::new(Level::Low,"Operation has security defined, but no 403 response defined",format!("swagger root path:{} method:{}",path,method)));
            }
        }
        alerts
    }
    //Checks for auth existance and type and alerts if non existant or basic
    fn check_auth(&self)->Vec<Alert>{
        let mut alerts = vec![];
        if let Some(sec_schemes) = get_auth(&self.swagger){
            for (s_name,s_scheme) in sec_schemes{
                let scheme = s_scheme.inner(&self.swagger_value);
                if let Some(s) = scheme.scheme{
                    if s == "basic"{
                        alerts.push(Alert::new(Level::High,"The API uses BASIC authentication, which is highly unrecommended",format!("swagger root components scheme:{}",s_name)));
                    }
                }
            }
        }else{
            alerts.push(Alert::new(Level::Medium,"The API doesn't have authentication defined","swagger root components".to_string()));
        }
        alerts
    }
    //Checks if the function uses the authentication scheme, and if the auth scheme is basic
    fn check_fn_auth(&self)->Vec<Alert>{
        let mut alerts = vec![];
        let general_auths:HashMap<String,SecScheme> = if let Some(auths) = get_auth(&self.swagger){ 
            auths.iter().map(|(s,r)| (s.clone(),r.inner(&self.swagger_value))).collect() 
        }else{
            return vec![];
        };
        for (path,item) in &self.swagger.paths{
            for (m,op) in item.get_ops(){
                let secs = if let Some(s) = &op.security { s.iter().map(|v| v.keys()).flatten().collect() } else { vec![] };
                if secs.len()==0{
                    alerts.push(Alert::new(Level::Medium,"Endpoint does not use any security scheme",format!("swagger root path:{} method:{}",path,m)));
                    continue;
                }
                for sec in secs{
                    if let Some(scheme) = general_auths.get(sec){
                        if let Some(s) = &scheme.scheme{
                            if s =="basic"{
                                alerts.push(Alert::new(Level::High,"The API uses BASIC authentication, which is highly unrecommended",format!("swagger root path:{} method:{} scheme:{}",path,m,sec)));
                            }
                        }
                    }else{
                        alerts.push(Alert::new(Level::Medium,"Endpoint with a security scheme that does not exist",format!("swagger root path:{} method:{}",path,m)));
                    }
                }
            }
        }
        alerts
    }
} 
