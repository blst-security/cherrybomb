use super::path::*;
use super::refs::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

//Info Object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct License {
    pub name: String,
    pub url: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Contact {
    pub name: Option<String>,
    pub url: Option<String>,
    pub email: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Info {
    pub title: String,
    pub description: Option<String>,
    #[serde(rename = "termsOfService")]
    pub tos: Option<String>,
    pub contact: Option<Contact>,
    pub license: Option<License>,
    pub version: String,
}
//End Info Object
//Server Object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ServerVariable {
    #[serde(rename = "enum")]
    pub var_enum: Option<Vec<String>>,
    pub default: String,
    pub description: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Server {
    #[serde(rename(deserialize = "url"))]
    pub base_url: String,
    pub description: Option<String>,
    pub variables: Option<HashMap<String, ServerVariable>>,
}

//End Server Object
//Path Object
pub type Security = HashMap<String, Vec<String>>;
pub type Callback = HashMap<String, HashMap<String, PathItem>>;
pub type Content = HashMap<String, MediaType>;
pub type Examples = HashMap<String, Example>;
pub type EncodingMap = HashMap<String, Encoding>;
//Practicaly Any
//type Schema = Value;
pub type HeaderMap = HashMap<String, HeaderRef>;
pub type Responses = HashMap<String, ResponseRef>;
pub type Links = HashMap<String, LinkRef>;
//Any
pub type LinkParameters = HashMap<String, Value>;
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Link {
    #[serde(rename = "operationRef")]
    pub operation_ref: Option<String>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub parameters: Option<LinkParameters>,
    //Any
    #[serde(rename = "requestBody")]
    pub request_body: Option<Value>,
    pub description: Option<String>,
    pub server: Option<Server>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Response {
    pub description: Option<String>,
    pub headers: Option<HeaderMap>,
    pub content: Option<Content>,
    pub links: Option<Links>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Header {
    pub description: Option<String>,
    pub required: Option<bool>,
    pub deprecated: Option<bool>,
    #[serde(rename = "allowEmptyValue")]
    pub allow_empty_value: Option<bool>,
    //Any
    pub example: Option<Value>,
    pub examples: Option<Examples>,
    pub style: Option<String>,
    pub explode: Option<bool>,
    #[serde(rename = "allowReserved")]
    pub allow_reserved: Option<bool>,
    pub schema: Option<SchemaRef>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Encoding {
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub headers: Option<HeaderMap>,
    pub style: Option<String>,
    pub explode: Option<bool>,
    #[serde(rename = "allowReserved")]
    pub allow_reserved: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MediaType {
    pub schema: Option<SchemaRef>,
    //Any
    pub example: Option<Value>,
    pub examples: Option<Examples>,
    pub encoding: Option<EncodingMap>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ExternalDocs {
    pub url: String,
    pub description: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ReqBody {
    pub description: Option<String>,
    pub content: Content,
    pub required: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Example {
    pub summary: Option<String>,
    pub description: Option<String>,
    //Any
    pub value: Value,
    #[serde(rename = "externalValue")]
    pub external_value: Option<String>,
}

//End Path Object

//Components Object
pub type Schemas = HashMap<String, SchemaRef>;
pub type Params = HashMap<String, ParamRef>;
pub type ReqBodies = HashMap<String, ReqRef>;
pub type SecSchemes = HashMap<String, SecSchemeRef>;
pub type CallbackComp = HashMap<String, PathItem>;
pub type Callbacks = HashMap<String, CallbackRef>;
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OAuth {
    #[serde(rename = "authorizationUrl")]
    pub authorization_url: Option<String>,
    #[serde(rename = "tokenUrl")]
    pub token_url: Option<String>,
    #[serde(rename = "refreshUrl")]
    pub refresh_url: Option<String>,
    pub scopes: HashMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OAuthFlows {
    pub implicit: Option<OAuth>,
    pub password: Option<OAuth>,
    #[serde(rename = "clientCredentials")]
    pub client_credentials: Option<OAuth>,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<OAuth>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SecScheme {
    #[serde(rename = "type")]
    pub tp: String,
    pub description: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "in")]
    pub scheme_in: Option<String>,
    pub scheme: Option<String>,
    #[serde(rename = "bearerFormat")]
    pub bearer_format: Option<String>,
    pub flows: Option<OAuthFlows>,
    pub openid_connect_url: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Components {
    pub schemas: Option<Schemas>,
    pub responses: Option<Responses>,
    pub parameters: Option<Params>,
    pub examples: Option<Examples>,
    #[serde(rename = "requestBodies")]
    pub request_bodies: Option<ReqBodies>,
    pub headers: Option<HeaderMap>,
    #[serde(rename = "securitySchemes")]
    pub security_schemes: Option<SecSchemes>,
    pub links: Option<Links>,
    pub callbacks: Option<Callbacks>,
}
//End Components Object

//Tag Object
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "externalDocs")]
    pub external_docs: Option<ExternalDocs>,
}
//End Tag Object

pub trait OAS {
    fn get_paths(&self) -> Paths;
    fn version(&self) -> String;
    fn info(&self) -> Info;
    fn servers(&self) -> Option<Vec<Server>>;
    fn components(&self) -> Option<Components>;
    fn security(&self) -> Option<Vec<Security>>;
    fn tags(&self) -> Option<Vec<Tag>>;
    fn ext_docs(&self) -> Option<ExternalDocs>;
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Swagger {
    pub openapi: String,
    pub info: Info,
    pub servers: Option<Vec<Server>>,
    pub paths: Paths,
    pub components: Option<Components>,
    pub security: Option<Vec<Security>>,
    pub tags: Option<Vec<Tag>>,
    #[serde(rename = "externalDocs")]
    pub external_docs: Option<ExternalDocs>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct OAS3_1 {
    pub openapi: String,
    pub info: Info,
    pub servers: Option<Vec<Server>>,
    pub webhooks: Option<Paths>,
    pub paths: Option<Paths>,
    pub components: Option<Components>,
    pub security: Option<Vec<Security>>,
    pub tags: Option<Vec<Tag>>,
    #[serde(rename = "externalDocs")]
    pub external_docs: Option<ExternalDocs>,
}
impl OAS for Swagger {
    fn get_paths(&self) -> Paths {
        self.paths.clone()
    }
    fn version(&self) -> String {
        self.openapi.clone()
    }
    fn info(&self) -> Info {
        self.info.clone()
    }
    fn servers(&self) -> Option<Vec<Server>> {
        self.servers.clone()
    }
    fn components(&self) -> Option<Components> {
        self.components.clone()
    }
    fn security(&self) -> Option<Vec<Security>> {
        self.security.clone()
    }
    fn tags(&self) -> Option<Vec<Tag>> {
        self.tags.clone()
    }
    fn ext_docs(&self) -> Option<ExternalDocs> {
        self.external_docs.clone()
    }
}
impl OAS for OAS3_1 {
    fn get_paths(&self) -> Paths {
        let mut paths = HashMap::new();
        if let Some(p) = self.paths.clone() {
            paths.extend(p);
        }
        if let Some(p) = self.webhooks.clone() {
            paths.extend(p);
        }
        paths
    }
    fn version(&self) -> String {
        self.openapi.clone()
    }
    fn info(&self) -> Info {
        self.info.clone()
    }
    fn servers(&self) -> Option<Vec<Server>> {
        self.servers.clone()
    }
    fn components(&self) -> Option<Components> {
        self.components.clone()
    }
    fn security(&self) -> Option<Vec<Security>> {
        self.security.clone()
    }
    fn tags(&self) -> Option<Vec<Tag>> {
        self.tags.clone()
    }
    fn ext_docs(&self) -> Option<ExternalDocs> {
        self.external_docs.clone()
    }
}
