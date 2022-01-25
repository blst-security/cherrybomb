use super::*;
use futures::executor;

#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Reference{
    #[serde(rename = "$ref")]
    pub param_ref:String,
}
impl Reference{
    pub fn get<T>(&self,swagger:&Value)->T
    where T:std::fmt::Debug+Clone+ Serialize+PartialEq+Eq+Default+for<'de>serde::Deserialize<'de>{
        if self.param_ref.starts_with('#'){
            let mut val = swagger;
                let split = self.param_ref.split("/").collect::<Vec<&str>>()[1..].to_vec();
                for s in split{
                    val = &val[s];
                }
                serde_json::from_value(val.clone()).unwrap()
        }else{
            match executor::block_on(self.get_external::<T>()){
                Ok(v)=>v,
                Err(e)=>panic!("{:?}",e),
            }
        }
    }
    pub async fn get_external<T>(&self)->Result<T,&'static str>
    where T:Clone+ Serialize+PartialEq+Eq+Default+for<'de>serde::Deserialize<'de>{
        match reqwest::get(&self.param_ref).await{
            Ok(res)=> {
                if res.status()==200{
                    if let Ok(json) = serde_json::from_str::<T>(&res.text().await.unwrap()){
                        Ok(json)

                    }else{
                        Err("Unable to deserialize external reference")
                    }
                }else{
                    Err("Fetching external refernece did not return OK status code")
                }
            },
            Err(_)=>Err("Could not fetch external reference")
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum ParamRef{
    Ref(Reference),
    Param(Parameter),
}
impl Default for ParamRef {
    fn default() -> Self {
        Self::Param(Parameter::default())
    }
}
#[allow(unused)]
impl ParamRef{
    pub fn inner(&self,swagger:&Value)->Parameter{
        match self{
            Self::Param(p) =>p.clone(),
            Self::Ref(r) =>r.get::<Parameter>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum ReqRef{
    Ref(Reference),
    Body(ReqBody),
}
impl Default for ReqRef {
    fn default() -> Self {
        Self::Body(ReqBody::default())
    }
}
#[allow(unused)]
impl ReqRef{
    pub fn inner(&self,swagger:&Value)->ReqBody{
        match self{
            Self::Body(p) =>p.clone(),
            Self::Ref(r) =>r.get::<ReqBody>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum SchemaRef{
    Ref(Reference),
    Schema(Schema),
}
impl Default for SchemaRef {
    fn default() -> Self {
        Self::Schema(Schema::default())
    }
}
#[allow(unused)]
impl SchemaRef{
    pub fn inner(&self,swagger:&Value)->Schema{
        match self{
            Self::Schema(p) =>{
                //println!("{:?}",p);
                p.clone()},
            Self::Ref(r) =>r.get::<Schema>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum HeaderRef{
    Ref(Reference),
    Header(Header),
}
impl Default for HeaderRef {
    fn default() -> Self {
        Self::Header(Header::default())
    }
}
#[allow(unused)]
impl HeaderRef{
    pub fn inner(&self,swagger:&Value)->Header{
        match self{
            Self::Header(p) =>p.clone(),
            Self::Ref(r) =>r.get::<Header>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum ResponseRef{
    Ref(Reference),
    Response(Response),
}
impl Default for ResponseRef {
    fn default() -> Self {
        Self::Response(Response::default())
    }
}
#[allow(unused)]
impl ResponseRef{
    pub fn inner(&self,swagger:&Value)->Response{
        match self{
            Self::Response(p) =>p.clone(),
            Self::Ref(r) =>r.get::<Response>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum LinkRef{
    Ref(Reference),
    Link(Link),
}
impl Default for LinkRef {
    fn default() -> Self {
        Self::Link(Link::default())
    }
}
#[allow(unused)]
impl LinkRef{
    pub fn inner(&self,swagger:&Value)->Link{
        match self{
            Self::Link(p) =>p.clone(),
            Self::Ref(r) =>r.get::<Link>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum SecSchemeRef{
    Ref(Reference),
    SecScheme(SecScheme),
}
impl Default for SecSchemeRef {
    fn default() -> Self {
        Self::SecScheme(SecScheme::default())
    }
}
#[allow(unused)]
impl SecSchemeRef{
    pub fn inner(&self,swagger:&Value)->SecScheme{
        match self{
            Self::SecScheme(p) =>p.clone(),
            Self::Ref(r) =>r.get::<SecScheme>(swagger),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize,PartialEq,Eq)]
#[serde(untagged)]
pub enum CallbackRef{
    Ref(Reference),
    CallbackComp(CallbackComp),
}
impl Default for CallbackRef {
    fn default() -> Self {
        Self::CallbackComp(CallbackComp::default())
    }
}
#[allow(unused)]
impl CallbackRef{
    pub fn inner(&self,swagger:&Value)->CallbackComp{
        match self{
            Self::CallbackComp(p) =>p.clone(),
            Self::Ref(r) =>r.get::<CallbackComp>(swagger),
        }
    }
}
