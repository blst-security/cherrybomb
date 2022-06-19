use super::*;
use std::fmt;
pub const LEFT_PAD: usize = 40;
pub const TBL_LEN: usize = 190;
pub const URL_LEN: usize = 75;

pub fn print_checks_table<T>(checks: &[T])
where
    T: fmt::Display + Check,
{
    println!(
        "{:pad$}| RESULT | TOP SEVERITY | ALERTS  |DESCRIPTION\n{:-<table_len$}",
        "CHECK",
        "",
        pad = LEFT_PAD,
        table_len = TBL_LEN
    );
    for check in checks {
        println!("{}", check);
    }
}
pub fn print_failed_checks_table<T>(checks: &[T])
where
    T: fmt::Display + Check,
{
    println!(
        "{:pad$}| RESULT | TOP SEVERITY | ALERTS  |DESCRIPTION\n{:-<table_len$}",
        "CHECK",
        "",
        pad = LEFT_PAD,
        table_len = TBL_LEN
    );
    for check in checks {
        if check.result() == "FAILED" {
            println!("{}", check);
        }
    }
}
fn split_text_to_lines(string: &str) -> Vec<String> {
    let mut new_vec = vec![];
    let mut new_str = String::new();
    let line_len = 75;
    let mut c = 0;
    for t in string.split(' ') {
        if !t.trim().is_empty() {
            c += t.len() + 1;
            if c > line_len {
                c = t.len();
                new_str.pop();
                new_vec.push(new_str);
                new_str = format!(" {}", t);
            } else {
                new_str.push_str(&format!("{} ", t.trim()));
            }
        }
    }
    new_vec.push(new_str);
    new_vec
}
pub fn print_alerts_table(checks: &[PassiveChecks]) {
    println!(
        "{:pad$}| LEVEL   |{:75}|DESCRIPTION\n{:-<table_len$}",
        "CHECK",
        "LOCATION",
        pad = 30,
        table_len = TBL_LEN
    );
    for check in checks {
        if check.result() == "FAILED" {
            for alert in check.inner() {
                println!("{:pad$}|{}", check.name().cyan().bold(), alert, pad = 30)
            }
        }
    }
}

pub fn print_attack_alerts_table(checks: &[ActiveChecks]) {
    println!(
        "{:pad$}| SEVERITY | CERTAINTY |{:thing$}|DESCRIPTION\n{:-<table_len$}",
        "CHECK",
        "LOCATION",
        "",
        table_len = TBL_LEN,
        pad = 30,
        thing = URL_LEN
    );
    for check in checks {
        if check.result() == "FAILED" {
            for _ in check.inner() {
                // println!("{:pad$}|{}", check.name().cyan().bold(), alert, pad = 30)
                println!("{}", serde_json::to_string(&check).unwrap());
            }
        }
    }
}

impl fmt::Display for PassiveChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.result() == "PASSED" {
            write!(
                f,
                "{:pad$}| {} |    {:8}  |  {:5}  |{}\n{:-<table_len$}",
                self.name().bold(),
                self.result().green().bold().underline(),
                "NONE".blue().bold(),
                self.alerts_text(),
                self.description(),
                "",
                pad = LEFT_PAD,
                table_len = TBL_LEN
            )
        } else if self.result() == "FAILED" {
            write!(
                f,
                "{:pad$}| {} |    {}  |  {:5}  |{}\n{:-<table_len$}",
                self.name().bold(),
                self.result().red().bold().underline(),
                self.top_severity(),
                self.alerts_text(),
                self.description(),
                "",
                pad = LEFT_PAD,
                table_len = TBL_LEN
            )
        } else {
            write!(f, "")
        }
    }
}

impl fmt::Display for ActiveChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.result() == "PASSED" {
            write!(
                f,
                "{:pad$}| {} |    {:8}  |  {:5}  |{}\n{:-<table_len$}",
                self.name().bold(),
                self.result().green().bold().underline(),
                "NONE".blue().bold(),
                self.alerts_text(),
                self.description(),
                "",
                pad = LEFT_PAD,
                table_len = TBL_LEN
            )
        } else if self.result() == "FAILED" {
            write!(
                f,
                "{:pad$}| {} |    {}  |  {:5}  |{}\n{:-<table_len$}",
                self.name().bold(),
                self.result().red().bold().underline(),
                self.top_severity(),
                self.alerts_text(),
                self.description(),
                "",
                pad = LEFT_PAD,
                table_len = TBL_LEN
            )
        } else {
            write!(f, "")
        }
    }
}
impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.certainty == Certainty::Passive {
            let location = self
                .location
                .replace("swagger root", "")
                .replace("swagger rooot", "")
                .replace("swagger", "")
                .replace("media type:application/json", "")
                .replace("response status", "status");
            let mut string = String::new();
            let location = split_text_to_lines(&location);
            string.push_str(&format!(
                " {:10}|{:75}|  {}\n",
                self.level,
                location[0].bright_magenta().bold(),
                self.description.bright_red().bold(),
            ));
            for loc in location.iter().skip(1) {
                string.push_str(&format!(
                    "{:30}|{:9}|{:75}|  {}\n",
                    "",
                    "",
                    loc.bright_magenta().bold(),
                    ""
                ));
            }
            string.push_str(&format!("\n{:-<190}", ""));
            write!(f, "{}", string)
        } else {
            /*write!(
                f,
                "  {}| {}  |{:thing$}|  {:}\n{:-<table_len$}",
                self.level,
                self.certainty,
                self.location.bright_magenta().bold(),
                self.description.bright_red().bold(),
                "",
                thing=URL_LEN,
                table_len = TBL_LEN
            )*/
            write!(f, "")
        }
    }
}
impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "{:8}", "INFO".blue().bold()),
            Self::Low => write!(f, "{:8}", "LOW".yellow().bold()),
            Self::Medium => write!(f, "{:8}", "MEDIUM".truecolor(255, 167, 38).bold()),
            Self::High => write!(f, "{:8}", "HIGH".red().bold()),
            Self::Critical => write!(f, "{:8}", "CRITICAL".red().bold().blink()),
        }
    }
}
impl fmt::Display for Certainty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "{:8}", "LOW".bright_black().bold()),
            Self::Medium => write!(
                f,
                "{:8}",
                "MEDIUM"
                    .bright_black() /*.truecolor(255, 167, 38)*/
                    .bold()
            ),
            Self::High => write!(f, "{:8}", "HIGH".bright_black().bold()),
            Self::Certain => write!(f, "{:8}", "CERTAIN".bright_black().bold()),
            Self::Passive => write!(f, ""),
        }
    }
}
