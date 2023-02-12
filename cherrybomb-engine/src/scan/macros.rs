#[macro_export]
macro_rules! impl_passive_checks{
    ( $( ($check:ident,$check_func:ident,$name:literal,$desc:literal )),* ) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq,Eq, EnumIter)]
        pub enum PassiveChecks{
            $(
                $check(Vec<Alert>),
            )*
        }
        impl PassiveChecks{
            pub fn from_string(string:&str)->Option<Self>{
                match string{
                    $(
                        $name=>Some(PassiveChecks::$check(vec![])),
                    )*
                    _=>None,
                }
            }
            pub fn description(&self)->&'static str{
                match &self{
                    $(
                        PassiveChecks::$check(_)=>$desc,
                    )*
                }
            }
            pub fn name(&self)->&'static str{
                match &self{
                    $(
                        PassiveChecks::$check(_)=>$name,
                    )*
                }
            }
            pub fn inner(&self)->Vec<Alert>{
                match &self{
                    $(
                        PassiveChecks::$check(i)=>i.to_vec(),
                    )*
                }
            }

        }
        impl <T:OAS+Serialize>PassiveSwaggerScan<T>{
            pub fn run_check(&self,check:PassiveChecks)->PassiveChecks{
                match check{
                    $(
                        PassiveChecks::$check(_)=>PassiveChecks::$check(self.$check_func()),
                    )*
                }
            }
        }
    }
}

#[macro_export]
macro_rules! impl_active_checks{
    ( $( ($check:ident,$check_func:ident,$response_func:ident,$name:literal,$desc:literal )),* ) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq,Eq, EnumIter)]
        pub enum ActiveChecks{
            $(
                $check((Vec<Alert>,AttackLog)),
            )*
        }
        impl ActiveChecks{
            pub fn description(&self)->&'static str{
                match &self{
                    $(
                        ActiveChecks::$check(_)=>$desc,
                    )*
                }
            }
            pub fn from_string(str1:&str)->Option<Self>{
                match str1{
                    $(
                        $name=>Some(ActiveChecks::$check((vec![],AttackLog::default()))),
                    )*
                    _=>None,
                }
            }
            pub fn name(&self)->&'static str{
                match &self{
                    $(
                        ActiveChecks::$check(_)=>$name,
                    )*
                }
            }
            pub fn inner(&self)->Vec<Alert>{
                match &self{
                    $(
                        ActiveChecks::$check(i)=>i.0.to_vec(),
                    )*
                }
            }
        }
        impl <T:OAS+Serialize>ActiveScan<T>{
            pub async fn run_check(&self,check:ActiveChecks,auth:&Authorization, serv: &Vec<Server>)->ActiveChecks{
                match check{
                    $(
                        ActiveChecks::$check(_)=>ActiveChecks::$check(Self::$response_func(self.$check_func(auth, serv).await)),
                    )*
                }
            }
        }
    }
}
