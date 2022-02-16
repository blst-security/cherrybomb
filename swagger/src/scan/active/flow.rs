use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FlowLink {}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FlowCondition {}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AlertFlag {}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttackFlow {
    requests: Vec<AttackRequest>,
    responses: Vec<AttackResponse>,
    links: Vec<FlowLink>,
    conditions: Vec<FlowCondition>,
    alert_flags: Vec<AlertFlag>,
}
