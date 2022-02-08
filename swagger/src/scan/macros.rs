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
    ( $( ($check:ident,$check_func:ident,$name:literal,$desc:literal )),* ) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq,Eq, EnumIter)]
        pub enum ActiveChecks{
            $(
                $check(Vec<Alert>),
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
                        ActiveChecks::$check(i)=>i.to_vec(),
                    )*
                }
            }
        }
        impl <T:OAS+Serialize>ActiveScan<T>{
            pub fn run_check(&self,check:ActiveChecks)->ActiveChecks{
                match check{
                    $(
                        ActiveChecks::$check(_)=>ActiveChecks::$check(self.$check_func()),
                    )*
                }
            }
        }
    }
}
