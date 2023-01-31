pub mod oas {
    use std::iter::Map;
    use serde_json::Value;

    pub trait OAS {
        fn get_paths(&self) -> Paths;
        fn version(&self) -> String;
        fn info(&self) -> Info;
        fn servers(&self) -> Option<Vec<Server>>;
        fn components(&self) -> Option<Components>;
        fn security(&self) -> Option<Vec<SecurityRequirement>>;
        fn tags(&self) -> Option<Vec<Tag>>;
        fn ext_docs(&self) -> Option<ExternalDocs>;
    }

    enum reffable<T> {
        Ref(String),
        Value(T),
    }

    pub struct OAS3_X {
        pub openapi: String,
        pub info: Info,
        pub servers: Option<Vec<Server>>,
        pub webhooks: Option<Map<String,reffable<PathItem>>>,
        pub paths: Option<Paths>,
        pub components: Option<Components>,
        pub security: Option<Vec<SecurityRequirement>>,
        pub tags: Option<Vec<Tag>>,
        #[serde(rename = "externalDocs")]
        pub external_docs: Option<ExternalDocs>,
    }

    struct Info {
        pub title: Option<String>,
        pub summary: Option<String>,
        pub description: Option<String>,
        #[serde(rename = "termsOfService")]
        pub terms_of_service: Option<String>,
        pub contact: Option<Contact>,
        pub license: Option<License>,
        pub version: String,
    }

    struct Contact {
        pub name: Option<String>,
        pub url: Option<String>,
        pub email: Option<String>,
    }

    struct License {
        pub name: Option<String>,
        pub identifier: Option<String>,
        pub url: Option<String>,
    }

    struct Server {
        #[serde(rename(deserialize = "url"))]
        pub base_url: Option<String>,
        pub description: Option<String>,
        pub variables: Option<Map<String,ServerVariable>>,
    }

    struct ServerVariable {
        #[serde(rename = "enum")]
        pub var_enum: Option<Vec<String>>,
        pub default: String,
        pub description: Option<String>,
    }

    struct Components {
        pub schemas: Option<Map<String,Schema>>,
        pub responses: Option<Map<String,reffable<Response>>>,
        pub parameters: Option<Map<String,reffable<Parameter>>>,
        pub examples: Option<Map<String,reffable<Example>>>,
        #[serde(rename = "requestBodies")]
        pub request_bodies: Option<Map<String,reffable<RequestBody>>>,
        pub headers: Option<Map<String,reffable<Header>>>,
        #[serde(rename = "securitySchemes")]
        pub security_schemes: Option<Map<String,reffable<SecurityScheme>>>,
        pub links: Option<Map<String,reffable<Link>>>,
        pub callbacks: Option<Map<String,reffable<Callback>>>,
        #[serde(rename = "pathItems")]
        pub path_items: Option<Map<String,reffable<PathItem>>>,
    }

    type Paths = Map<String,PathItem>;

    struct PathItem {
        summary: Option<String>,
        description: Option<String>,
        get: Option<Operation>,
        put: Option<Operation>,
        post: Option<Operation>,
        delete: Option<Operation>,
        options: Option<Operation>,
        head: Option<Operation>,
        patch: Option<Operation>,
        trace: Option<Operation>,
        servers: Option<Vec<Server>>,
        parameters: Option<Vec<reffable<Parameter>>>,
    }

    struct Operation {
        pub tags: Option<Vec<String>>,
        pub summary: Option<String>,
        pub description: Option<String>,
        #[serde(rename = "externalDocs")]
        pub external_docs: Option<ExternalDocs>,
        #[serde(rename = "operationId")]
        pub operation_id: Option<String>,
        pub parameters: Option<Vec<reffable<Parameter>>>,
        #[serde(rename = "requestBody")]
        pub request_body: Option<reffable<RequestBody>>,
        pub responses: Map<String,Response>,
        pub callbacks: Option<Map<String,reffable<Callback>>>,
        pub deprecated: Option<bool>,
        pub security: Option<Vec<Security>>,
        pub servers: Option<Vec<Server>>,
    }

    struct ExternalDocs {
        pub description: Option<String>,
        pub url: Option<String>,
    }

    struct Parameter {
        pub name: Option<String>,
        #[serde(rename = "in")]
        pub in_field: Option<String>,
        pub description: Option<String>,
        pub required: Option<bool>,
        pub deprecated: Option<bool>,
        #[serde(rename = "allowEmptyValue")]
        pub allow_empty_value: Option<bool>,
        pub style: Option<String>,
        pub explode: Option<bool>,
        #[serde(rename = "allowReserved")]
        pub allow_reserved: Option<bool>,
        pub schema: Option<Schema>,
        pub example: Option<serde_json::Value>,
        pub examples: Option<Map<String,reffable<Example>>>,
        pub content: Option<Map<String,MediaType>>,
    }

    struct RequestBody {
        pub description: Option<String>,
        pub content: Option<Map<String,MediaType>>,
        pub required: Option<bool>,
    }

    struct MediaType {
        pub schema: Option<Schema>,
        pub example: Option<serde_json::Value>,
        pub examples: Option<Map<String,reffable<Example>>>,
        pub encoding: Option<Map<String,Encoding>>,
    }

    struct Encoding {
        pub contentType: Option<String>,
        pub headers: Option<Map<String,reffable<Header>>>,
        pub style: Option<String>,
        pub explode: Option<bool>,
        #[serde(rename = "allowReserved")]
        pub allow_reserved: Option<bool>,
    }

    type Responses = Map<String,Response>;

    struct Response {
        pub description: String,
        pub headers: Option<Map<String,reffable<Header>>>,
        pub content: Option<Map<String,MediaType>>,
        pub links: Option<Map<String,reffable<Link>>>,
    }

    struct Callback {
        pub path: Option<String>,
        pub operation: Option<Operation>,
    }

    struct Example {
        pub summary: Option<String>,
        pub description: Option<String>,
        pub value: Option<serde_json::Value>,
        pub externalValue: Option<String>,
    }

    struct Link {
        #[serde(rename = "operationRef")]
        pub operation_ref: Option<String>,
        #[serde(rename = "operationId")]
        pub operation_id: Option<String>,
        pub parameters: Option<Map<String,serde_json::Value>>,
        #[srede(rename = "requestBody")]
        pub request_body: Option<serde_json::Value>,
        pub description: Option<String>,
        pub server: Option<Server>,
    }

    struct Header {
        pub description: Option<String>,
        pub required: Option<bool>,
        pub deprecated: Option<bool>,
        #[serde(rename = "allowEmptyValue")]
        pub allow_empty_value: Option<bool>,
        pub style: Option<String>,
        pub explode: Option<bool>,
        #[serde(rename = "allowReserved")]
        pub allow_reserved: Option<bool>,
        pub schema: Option<Schema>,
        pub example: Option<serde_json::Value>,
        pub examples: Option<Map<String,reffable<Example>>>,
        pub content: Option<Map<String,MediaType>>,
    }

    struct Tag {
        pub name: Option<String>,
        pub description: Option<String>,
        #[serde(rename = "externalDocs")]
        pub external_docs: Option<ExternalDocs>,
    }

    struct Reference {
        #[serde(rename = "$ref")]
        pub ref_field: Option<String>,
        pub summary: Option<String>,
        pub description: Option<String>,
    }

    struct Schema {
        pub discriminator: Option<Discriminator>,
        pub xml: Option<XML>,
        #[serde(rename = "externalDocs")]
        pub external_docs: Option<ExternalDocs>,
        pub example: Option<serde_json::Value>,
    }

    struct Discriminator {
        pub propertyName: Option<String>,
        pub mapping: Option<Map<String,String>>,
    }

    struct XML {
        pub name: Option<String>,
        pub namespace: Option<String>,
        pub prefix: Option<String>,
        pub attribute: Option<bool>,
        pub wrapped: Option<bool>,
    }

    struct SecurityScheme {
        #[serde(rename = "type")]
        pub type_field: Option<String>,
        pub description: Option<String>,
        pub name: Option<String>,
        pub in_field: Option<String>,
        pub scheme: Option<String>,
        #[serde(rename = "bearerFormat")]
        pub bearer_format: Option<String>,
        pub flows: Option<OAuthFlows>,
        #[serde(rename = "openIdConnectUrl")]
        pub open_id_connect_url: Option<String>,
    }

    struct OAuthFlows {
        pub implicit: Option<OAuthFlow>,
        pub password: Option<OAuthFlow>,
        #[serde(rename = "clientCredentials")]
        pub client_credentials: Option<OAuthFlow>,
        pub authorizationCode: Option<OAuthFlow>,
    }

    struct OAuthFlow {
        #[serde(rename = "authorizationUrl")]
        pub authorization_url: Option<String>,
        #[serde(rename = "tokenUrl")]
        pub token_url: Option<String>,
        #[serde(rename = "refreshUrl")]
        pub refresh_url: Option<String>,
        pub scopes: Option<Map<String,String>>,
    }

    struct SecurityRequirement {
        pub name: Option<String>,
        pub scopes: Option<Vec<String>>,
    }

    type Security = HashMap<String, Vec<String>>;

}