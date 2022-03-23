use super::*;
use std::fmt;
pub const LEFT_PAD: usize = 40;
pub const TBL_LEN: usize = 250;
pub const URL_LEN: usize = 75;

pub fn print_checks_table<T>(checks: &[T]) 
where T:fmt::Display+Check{
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
where T:fmt::Display+Check{
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

pub fn print_alerts_table(checks: &[PassiveChecks]) {
    println!(
        "{:pad$}| LEVEL   |{:150}|DESCRIPTION\n{:-<table_len$}",
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
/*
pub fn print_attack_alerts_table(checks: &[ActiveChecks]) {
    println!(
        "{:pad$}| SEVERITY | CERTAINTY |{:thing$}|DESCRIPTION\n{:-<table_len$}",
        "CHECK",
        "LOCATION",
        "",
        table_len = TBL_LEN,
        pad = 30,
        thing=URL_LEN
    );
    for check in checks {
        if check.result() == "FAILED" {
            for alert in check.inner() {
                println!("{:pad$}|{}", check.name().cyan().bold(), alert, pad = 30)
            }
        }
    }
}*/

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
/*
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
}*/
impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.certainty==Certainty::Passive{
            let location = self
                .location
                .replace("swagger root", "")
                .replace("swagger rooot", "")
                .replace("swagger", "")
                .replace("media type:application/json", "")
                .replace("response status", "status");
            write!(
                f,
                " {}|{:150}|  {:}\n{:-<table_len$}",
                self.level,
                location.bright_magenta().bold(),
                self.description.bright_red().bold(),
                "",
                table_len = TBL_LEN
            )
        }else{
            write!(
                f,
                "  {}| {}  |{:thing$}|  {:}\n{:-<table_len$}",
                self.level,
                self.certainty,
                self.location.bright_magenta().bold(),
                self.description.bright_red().bold(),
                "",
                thing=URL_LEN,
                table_len = TBL_LEN
            )
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
            Self::Medium => write!(f, "{:8}", "MEDIUM".bright_black()/*.truecolor(255, 167, 38)*/.bold()),
            Self::High => write!(f, "{:8}", "HIGH".bright_black().bold()),
            Self::Certain => write!(f, "{:8}", "CERTAIN".bright_black().bold()),
            Self::Passive=> write!(f, ""),
        }
    }
}
