use super::*;
mod param_table;
pub use param_table::*;
mod ep_table;
use colored::*;
pub use ep_table::*;
pub fn color_status(string: &str) -> ColoredString {
    match string.to_lowercase().chars().next().unwrap_or(' ') {
        'd' => string.bold().truecolor(107, 114, 128),
        '2' => string.bold().truecolor(134, 239, 172),
        '3' => string.bold().truecolor(147, 197, 253),
        '4' => string.bold().truecolor(253, 224, 71),
        '5' => string.bold().truecolor(239, 68, 68),
        _ => string.bold(),
    }
}
//value_from_vec
pub fn vv<T>(vec: &[T], loc: usize) -> String
where
    T: Clone + std::fmt::Display,
{
    if vec.len() > loc {
        vec[loc].to_string()
    } else {
        String::new()
    }
}
