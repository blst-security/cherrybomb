use thiserror::Error;

#[allow(dead_code)]
/// Custom error format example
#[derive(Error, Debug)]
pub enum MyError {
    #[error("Custom error {0}")]
    One(String),
}
