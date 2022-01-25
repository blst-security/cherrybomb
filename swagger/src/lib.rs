use serde::{Serialize,Deserialize};
use serde_json::Value;
//use serde_yaml::Value;
use std::collections::HashMap;
mod refs;
use refs::*;
mod path;
use path::*;
mod param;
use param::*;
mod schema;
use schema::*;
mod ep;
use ep::*;
mod scan;
use scan::*;
use mapper::digest::{Digest,Method,Split,ParamDescriptor,QuePay,ValueDescriptor,Endpoint,ParamPayload,RRPayload,HeaderMap as OtherHeaderMap,PayloadDescriptor};
use mapper::path::{Path as DPath};

//Info Object
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct License{
    name:String,
    url:Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Contact{
    name:Option<String>,
    url:Option<String>,
    email:Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Info{
    title:String,
    description:Option<String>,
    #[serde(rename = "termsOfService")]
    tos:Option<String>,
    contact:Option<Contact>,
    license:Option<License>,
    version:String,
}
//End Info Object
//Server Object
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct ServerVariable{
    #[serde(rename = "enum")]
    var_enum:Option<Vec<String>>,
    default:String,
    description:Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Server{
    pub url:String,
    description:Option<String>,
    variables:Option<HashMap<String,ServerVariable>>,
}

//End Server Object
//Path Object
type Security = HashMap<String,Vec<String>>;
type Callback = HashMap<String,HashMap<String,PathItem>>;
type Content = HashMap<String,MediaType>;
type Examples = HashMap<String,Example>;
type EncodingMap = HashMap<String,Encoding>;
//Practicaly Any
//type Schema = Value;
type HeaderMap = HashMap<String,HeaderRef>;
type Responses = HashMap<String,ResponseRef>;
type Links = HashMap<String,LinkRef>;
//Any
type LinkParameters = HashMap<String,Value>;
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Link{
    #[serde(rename = "operationRef")]
    operation_ref:Option<String>,
    #[serde(rename = "operationId")]
    oeration_id:Option<String>,
    parameters:Option<LinkParameters>,
    //Any
    #[serde(rename = "requestBody")]
    request_body:Option<Value>,
    description:Option<String>,
    server:Option<Server>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Response{
    description:String,
    headers:Option<HeaderMap>,
    content:Option<Content>,
    links:Option<Links>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Header{
    description:Option<String>,
    required:bool,
    deprecated:Option<bool>,
    #[serde(rename = "allowEmptyValue")]
    allow_empty_value:Option<bool>,
    //Any
    example:Option<Value>,
    examples:Option<Examples>,
    style:Option<String>,
    explode:Option<bool>,
    #[serde(rename = "allowReserved")]
    allow_reserved:Option<bool>,
    schema:Option<SchemaRef>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Encoding{
    #[serde(rename = "contentType")]
    conent_type:Option<String>,
    headers:Option<HeaderMap>,
    style:Option<String>,
    explode:Option<bool>,
    #[serde(rename = "allowReserved")]
    allow_reserved:Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct MediaType{
    pub schema:Option<SchemaRef>,
    //Any
    example:Option<Value>,
    examples:Option<Examples>,
    encoding:Option<EncodingMap>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct ExternalDocs{
    url:String,
    description:Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct ReqBody{
    description:Option<String>,
    pub content:Content,
    required:Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Example{
    summary:Option<String>,
    description:Option<String>,
    //Any
    value:Value,
    #[serde(rename = "externalValue")]
    external_value:Option<String>,

}

//End Path Object

//Components Object
type Schemas = HashMap<String,SchemaRef>;
type Params = HashMap<String,ParamRef>;
type ReqBodies = HashMap<String,ReqRef>;
type SecSchemes = HashMap<String,SecSchemeRef>;
type CallbackComp = HashMap<String,PathItem>;
type Callbacks = HashMap<String,CallbackRef>;
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct OAuth{
    #[serde(rename = "authorizationUrl")]
    authorization_url:String,
    #[serde(rename = "tokenUrl")]
    token_uri:String,
    #[serde(rename = "refreshUrl")]
    refresh_uri:Option<String>,
    scopes:HashMap<String,String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct OAuthFlows{
    implicit:Option<OAuth>,
    password:Option<OAuth>,
    #[serde(rename = "clientCredentials")]
    client_credentials:Option<OAuth>,
    #[serde(rename = "authorizationCode")]
    authorization_code:Option<OAuth>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct SecScheme{
    #[serde(rename = "type")]
    pub tp:String,
    description:Option<String>,
    name:Option<String>,
    #[serde(rename = "in")]
    scheme_in:Option<String>,
    pub scheme:Option<String>,
    #[serde(rename = "bearerFormat")]
    bearer_format:Option<String>,
    flows:Option<OAuthFlows>,
    openid_connect_url:Option<String>,
}    
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Components{
    schemas:Option<Schemas>,
    responses:Option<Responses>,
    parameters:Option<Params>,
    examples:Option<Examples>,
    #[serde(rename = "requestBodies")]
    request_bodies:Option<ReqBodies>,
    headers:Option<HeaderMap>,
    #[serde(rename = "securitySchemes")]
    security_schemes:Option<SecSchemes>,
    links:Option<Links>,
    callbacks:Option<Callbacks>,
}
//End Components Object

//Tag Object
#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Tag{
    name:String,
    description:Option<String>,
    #[serde(rename = "externalDocs")]
    external_docs:Option<ExternalDocs>,
}
//End Tag Object

#[derive(Debug, Clone, Serialize, Deserialize, Default,PartialEq,Eq)]
pub struct Swagger{
    openapi:String,
    info:Info,
    servers:Option<Vec<Server>>,
    paths:Path,
    components:Option<Components>,
    security:Option<Vec<Security>>,
    tags:Option<Vec<Tag>>,
    #[serde(rename = "externalDocs")]
    external_docs:Option<ExternalDocs>,
}
impl Swagger{
    /*pub fn fingerprint(&self,swagger_value:&Value)->Vec<Alert>{
        let mut alerts = vec![];
        let mut eps = vec![];
        for (_path,item) in &self.paths{
            eps.extend(item.get_possible_eps(swagger_value,_path.to_string()));
        }
        for ep in eps.iter(){
            alerts.extend(ep.scan());
        }
        //println!("{:?}",serde_json::to_string(&eps).unwrap());
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).create(true).open("test1.json").unwrap();
            let ff = serde_json::to_string(&eps).unwrap();
            f.write_all(ff.as_bytes()).unwrap();
        alerts
    }*/
    pub fn convert_to_map(&self,swagger_value:Value)->Digest{
        let a = PassiveSwaggerScan::new(swagger_value.clone()).run(ScanType::Full);
        print_checks_table(&a);
        print_alerts_table(&a);
        let mut eps:Vec<Endpoint> = vec![];
       // let _ = self.fingerprint(&swagger_value);
        let _paths:HashMap<String,PathItem> = self.paths.iter().enumerate().map(|(_i,(path,item))|{
            let methods:HashMap<Method,u32> = item.get_ops().iter().map(|o| (o.0.clone(),1u32)).collect();
            let dm = item.params().iter().map(|p| {
                (p.inner(&swagger_value).from(),1u32)
            }).collect();
            let mut queries = vec![];
            for param in item.params(){
                let inner = param.inner(&swagger_value);
                if let QuePay::Query = inner.from(){
                    //needs payload assesment
                    queries.push(ParamPayload{param:inner.name(),payload:String::new()});
                }
            }
            eps.push(Endpoint{
                path:item.into_digest_path(path.to_string(),&swagger_value),
                methods:Split::from_hashmap(&methods),
                payload_delivery_methods:Split::from_hashmap(&dm),
                common_req_headers:OtherHeaderMap::default(),
                common_res_headers:OtherHeaderMap::default(),
                req_res_payloads:RRPayload::default(),
            });
            (path.clone(),item.clone())
        }).collect();
        Digest::default()
    }
}
