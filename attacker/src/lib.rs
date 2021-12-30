use decider::Anomaly;
use mapper::digest::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;

mod genetic;
pub use genetic::*;
mod genome;
use genome::*;
mod attack;
use attack::*;
mod auth;
pub use auth::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attacker {
    base_url: String,
    populations: Vec<Population>,
}
const FILE: &str = "attacker.json";
impl Attacker {
    pub fn save(&self) -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(FILE)?;
        file.write_all(serde_json::to_string(&self).unwrap().as_bytes())?;
        Ok(())
    }
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::read_to_string(FILE)?;
        let a: Attacker = serde_json::from_str(&file)?;
        Ok(a)
    }
}
pub fn prepare(digest: Digest, base_url: String) -> Vec<Vec<String>> {
    let mut groups = vec![];
    let mut populations = vec![];
    for group in digest.groups {
        populations.push(Population::new(&group, 400, 50, None, 20, 10));
        groups.push(
            group
                .endpoints
                .iter()
                .map(|e| e.path.path_ext.clone())
                .collect::<Vec<String>>(),
        );
    }
    let a = Attacker {
        populations,
        base_url,
    };
    a.save().unwrap();
    groups
}
pub fn get_populations() -> Vec<Vec<String>> {
    let attacker = if let Ok(a) = Attacker::load() {
        a
    } else {
        return vec![];
    };
    attacker.populations.iter().map(|p| p.endpoints()).collect()
}
pub fn refit(pop: usize, anomalies: Vec<Option<Anomaly>>, anomaly_scores: Vec<Vec<u16>>) {
    let mut attacker = if let Ok(a) = Attacker::load() {
        a
    } else {
        return;
    };
    attacker.populations[pop].refit(anomalies, anomaly_scores);
    attacker.save().unwrap();
}
pub async fn attack(
    pop: usize,
    verbosity: Verbosity,
    decide_file: &str,
    headers: &[Header],
    auth: &Authorization,
) -> Result<Vec<Session>, &'static str> {
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .open(decide_file)
    {
        if let Ok(attacker) = Attacker::load() {
            let sessions = attacker.populations[pop]
                .run_gen(verbosity, &attacker.base_url, headers, auth)
                .await;
            file.write_all(serde_json::to_string(&sessions).unwrap().as_bytes())
                .unwrap();
            attacker.save().unwrap();
            Ok(sessions)
        } else {
            Err("Unable to load attacker module, needs to be prepared first")
        }
    } else {
        Err("Unable to open decider file")
    }
}
