use super::*;
mod req;
pub use req::*;
mod auth;
pub use auth::*;
use mapper::digest::Header as MHeader;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RequestParameter {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing)]
    pub dm: QuePay,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackResponse {
    pub status: u16,
    pub payload: String,
    pub headers: HashMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackRequest {
    pub path: String,
    pub parameters: Vec<RequestParameter>,
    pub payload: String,
    pub auth: Authorization,
    pub method: Method,
    pub headers: Vec<MHeader>,
}
