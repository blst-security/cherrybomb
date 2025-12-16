use cherrybomb_engine::config::{Profile, Verbosity};
use std::io::{Read, Write};
use uuid::Uuid;

pub async fn send(profile: Profile, verbosity: Verbosity) -> anyhow::Result<()> {
    if let Verbosity::Debug = verbosity {
        println!("Sending telemetry data to Cherrybomb servers");
    };
    let profile = match profile {
        Profile::Info => "ep_table",
        Profile::Normal => "passive and active oas scan",
        Profile::Active => "active oas scan",
        Profile::Passive => "passive oas scan",
        Profile::Full => "passive and active oas scan",
        Profile::OWASP => "active oas scan",
    };
    let token = match get_token(verbosity) {
        Ok(token) => token,
        Err(e) => Err(anyhow::anyhow!(
            "Error getting telemetry token: {e}\
                                                \nTry to run with --no_telemetry"
        ))?,
    };
    let response = reqwest::Client::new()
        .post("https://cherrybomb.blstsecurity.com/tel")
        .body(format!(
            "{{\"client_token\":\"{token}\",\"event\":\"{profile}\"}}"
        ))
        .send()
        .await?;
    match response.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            let response = response.text().await?;
            Err(anyhow::anyhow!(
                "Error sending telemetry request: {response}"
            ))?
        }
    }
}

fn get_token(verbosity: Verbosity) -> anyhow::Result<Uuid> {
    if let Verbosity::Debug = verbosity {
        println!("Getting telemetry token")
    };
    let mut token_path = dirs::home_dir().ok_or(anyhow::anyhow!("Cant locate home directory"))?;
    token_path.push(".cherrybomb");
    token_path.push("token");
    if token_path.exists() {
        let mut token_file = std::fs::File::open(token_path)?;
        let mut token = String::new();
        token_file.read_to_string(&mut token)?;
        Ok(Uuid::parse_str(&token)?)
    } else {
        let token = Uuid::new_v4();
        let mut token_path =
            dirs::home_dir().ok_or(anyhow::anyhow!("Cant locate home directory"))?;
        token_path.push(".cherrybomb");
        std::fs::create_dir_all(&token_path)?;
        token_path.push("token");
        let mut token_file = std::fs::File::create(token_path)?;
        token_file.write_all(token.to_string().as_bytes())?;
        Ok(token)
    }
}
