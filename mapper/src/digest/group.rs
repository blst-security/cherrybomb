use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Link {
    pub from: Endpoint,
    pub to: Endpoint,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
pub struct GroupLink {
    pub from: Endpoint,
    pub to: Endpoint,
    pub strength: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Group {
    pub endpoints: Vec<Endpoint>,
    pub links: Vec<GroupLink>,
}
