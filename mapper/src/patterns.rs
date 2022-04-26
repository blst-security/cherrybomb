use super::*;
fn fingerprint_string(strings: Vec<&String>) -> StringDescriptor {
    if let Ok(u) = Uuid::parse_str(strings[0]) {
        match u.get_version() {
            Some(Version::Nil) => StringDescriptor::Uuid(0),
            Some(Version::Mac) => StringDescriptor::Uuid(1),
            Some(Version::Dce) => StringDescriptor::Uuid(2),
            Some(Version::Md5) => StringDescriptor::Uuid(3),
            Some(Version::Random) => StringDescriptor::Uuid(4),
            Some(Version::Sha1) => StringDescriptor::Uuid(5),
            None => StringDescriptor::Uuid(255),
        }
    } else {
        let mut fp_hash = HashSet::new();
        for string in strings {
            fp_hash.insert(string.to_string());
            if fp_hash.len() > 100 {
                return StringDescriptor::Random;
            }
        }
        StringDescriptor::List(fp_hash.into_iter().collect())
    }
}
fn fingerprint_number(numbers: Vec<&String>) -> ValueDescriptor {
    let mut fp_hash = HashSet::new();
    let mut nt = NumType::Integer;
    let mut lowest = 0f64;
    let mut highest = 0f64;
    for number in numbers {
        if let Ok(num) = number.parse::<f64>() {
            fp_hash.insert(num as i64);
            if num.trunc() != num {
                nt = NumType::Float;
            }
            if num < lowest {
                lowest = num;
            } else if num > highest {
                highest = num;
            }
        } else {
            return ValueDescriptor::Unknown;
        }
    }
    if fp_hash.len() < 100 {
        ValueDescriptor::Number((NumDescriptor::List(fp_hash.into_iter().collect()), nt))
    } else {
        ValueDescriptor::Number((NumDescriptor::Range((lowest as i64, highest as i64)), nt))
    }
}
pub fn search_for_patterns(values: Vec<&String>) -> ValueDescriptor {
    let pointers = values.iter().take(10);
    if pointers.len()==0{
        return ValueDescriptor::default();
    }
    let mut weights = (0u16, 0u16, 0u16);
    for pointer in pointers.clone(){
        if pointer.parse::<f64>().is_ok() {
            weights.0 += 1;
        } else if pointer.parse::<bool>().is_ok() {
            weights.1 += 1;
        } else {
            weights.2 += 1;
        }
    }
    let len1 = pointers.clone().len() as u16;
    match (
        weights.0 * 100 / len1 > 75,
        weights.1 * 100 / len1 > 75,
        weights.2 * 100 / len1 > 75,
    ) {
        (true, ..) => fingerprint_number(values),
        (false, true, false) => ValueDescriptor::Bool,
        (.., true) => ValueDescriptor::String(fingerprint_string(values)),
        (false, false, false) => ValueDescriptor::default(),
    }
}
