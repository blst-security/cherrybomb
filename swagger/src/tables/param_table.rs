use super::*;
use colored::*;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct ParamForTableKey {
    name: String,
    #[serde(rename = "type")]
    param_type: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamForTableValue {
    eps: HashSet<String>,
    dms: HashSet<QuePay>,
    statuses: HashSet<String>,
    parents: HashSet<String>,
    children: HashSet<String>,
    max: Option<i64>,
    min: Option<i64>,
    //default:Option<SchemaStrInt>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamForTable {
    pub name: String,
    //probably will become an Enum
    #[serde(rename = "type")]
    param_type: String,
    statuses: Vec<String>,
    //probably will become an Enum
    //from:String,
    dms: Vec<QuePay>,
    eps: Vec<String>,
    parents: Vec<String>,
    children: Vec<String>,
    max: Option<i64>,
    min: Option<i64>,
    //default:Option<SchemaStrInt>,
}
//value_from_vec
fn vv<T>(vec: &[T], loc: usize) -> String
where
    T: Clone + std::fmt::Display,
{
    if vec.len() > loc {
        vec[loc].to_string()
    } else {
        String::new()
    }
}
fn color_status(string: &str) -> ColoredString {
    match string.to_lowercase().chars().next().unwrap_or(' ') {
        'd' => string.bold().truecolor(107, 114, 128),
        '2' => string.bold().truecolor(134, 239, 172),
        '3' => string.bold().truecolor(147, 197, 253),
        '4' => string.bold().truecolor(253, 224, 71),
        '5' => string.bold().truecolor(239, 68, 68),
        _ => string.bold(),
    }
}
fn color_type(string: &str) -> ColoredString {
    match string.to_lowercase().as_str() {
        "object" => string.bold().truecolor(248, 113, 113),
        "array" => string.bold().truecolor(251, 146, 60),
        "string" => string.bold().truecolor(190, 242, 100),
        "number" => string.bold().truecolor(125, 211, 252),
        "integer" => string.bold().truecolor(167, 139, 250),
        "boolean" => string.bold().truecolor(253, 224, 71),
        _ => string.bold(),
    }
}
impl fmt::Display for ParamForTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max = if let Some(m) = self.max {
            m.to_string()
        } else {
            "NULL".to_string()
        };
        let min = if let Some(m) = self.min {
            m.to_string()
        } else {
            "NULL".to_string()
        };
        let min_max = format!("{}-{}", min, max);
        let lines = *([
            self.statuses.len(),
            self.dms.len(),
            self.parents.len(),
            self.children.len(),
            self.eps.len(),
        ]
        .iter()
        .max()
        .unwrap_or(&0));
        let mut string = String::new();
        let name_len = *([self.name.len(), 25].iter().min().unwrap_or(&0));
        let parent = vv(&self.parents, 0);
        let parent = &parent[0..*([parent.len(), 25].iter().min().unwrap_or(&0))];
        let child = vv(&self.children, 0);
        let child = &child[0..*([child.len(), 25].iter().min().unwrap_or(&0))];
        let ep = vv(&self.eps, 0);
        let ep = &ep[0..*([ep.len(), 75].iter().min().unwrap_or(&0))];
        string.push_str(&format!(
            "{:25}|{:7}|{:10}|{:16}|{:75}|{:25}|{:25}|{:15}\n",
            &self.name.bold()[..name_len],
            color_type(&self.param_type),
            color_status(&vv(&self.statuses, 0)),
            vv(&self.dms, 0).bold(),
            ep.bold().bright_cyan(),
            parent.bold(),
            child.bold(),
            min_max.bold()
        ));
        for i in 1..lines {
            let parent = vv(&self.parents, i);
            let parent = &parent[0..*([parent.len(), 25].iter().min().unwrap_or(&0))];
            let child = vv(&self.children, i);
            let child = &child[0..*([child.len(), 25].iter().min().unwrap_or(&0))];
            let ep = vv(&self.eps, i);
            let ep = &ep[0..*([ep.len(), 75].iter().min().unwrap_or(&0))];
            string.push_str(&format!(
                "{:25}|{:7}|{:10}|{:16}|{:75}|{:25}|{:25}|{:15}\n",
                "",
                "",
                color_status(&vv(&self.statuses, i)),
                vv(&self.dms, i),
                ep.bold().bright_cyan(),
                parent.bold(),
                child.bold(),
                ""
            ));
        }
        string.push_str(&format!("{:-<210}", ""));
        write!(f, "{}", string)
    }
}
impl ParamForTable {
    pub fn from_hash(hash: HashMap<ParamForTableKey, ParamForTableValue>) -> Vec<ParamForTable> {
        let mut vec = vec![];
        for (key, value) in hash {
            vec.push(ParamForTable {
                name: key.name,
                param_type: key.param_type,
                statuses: value.statuses.iter().cloned().collect(),
                dms: value.dms.iter().cloned().collect(),
                eps: value.eps.iter().cloned().collect(),
                parents: value.parents.iter().cloned().collect(),
                children: value.children.iter().cloned().collect(),
                max: value.max,
                min: value.min,
            });
        }
        vec
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParamTable {
    info: Info,
    servers: Vec<String>,
    pub params: Vec<ParamForTable>,
    eps: Vec<String>,
}
impl ParamTable {
    pub fn print(&self) {
        //println!("info:{:?}",self.info);
        //println!("urls:{:?}",self.servers);
        //println!("eps:{:?}",self.eps);
        let head = format!(
            "{:25}|{:7}|{:10}|{:16}|{:75}|{:25}|{:25}|{:15}",
            "NAME".bold().underline(),
            "TYPE".bold().underline(),
            "STATUSES".bold().underline(),
            "DELIVERY METHODS".bold().underline(),
            "ENDPOINTS".bold().underline(),
            "PARENTS".bold().underline(),
            "CHILDREN".bold().underline(),
            "MIN-MAX".bold().underline()
        );
        //println!("{}\n{:-<270}",head,"");
        for (i, param) in self.params.iter().enumerate() {
            if i % 50usize == 0 {
                println!("{}\n{:-<210}", head, "");
            }
            println!("{}", param);
        }
        //println!("{}",head);
    }
    pub fn named_param(&self, param: &str) -> Self {
        let params = self
            .params
            .iter()
            .filter(|p| p.name.as_str() == param)
            .cloned()
            .collect::<Vec<ParamForTable>>();
        ParamTable {
            info: self.info.clone(),
            servers: self.servers.clone(),
            params,
            eps: self.eps.clone(),
        }
    }
    pub fn new<T>(value: &Value) -> Self
    where
        T: Clone + OAS + for<'de> serde::Deserialize<'de>,
    {
        let oas = serde_json::from_value::<T>(value.clone()).unwrap();
        ParamTable {
            info: oas.info(),
            servers: oas
                .servers()
                .unwrap_or_default()
                .iter()
                .map(|s| s.url.clone())
                .collect(),
            params: Self::get_params(&oas, value),
            eps: oas.get_paths().iter().map(|(p, _)| p).cloned().collect(),
        }
    }
    fn get_all_possible_schemas(schema: &Schema) -> Vec<SchemaRef> {
        let mut schemas = vec![];
        if let Some(items) = schema.items.clone() {
            schemas.push(*items);
        }
        if let Some(any) = schema.any_of.clone() {
            schemas.extend(any);
        }
        if let Some(all) = schema.all_of.clone() {
            schemas.extend(all);
        }
        if let Some(one) = schema.one_of.clone() {
            schemas.extend(one);
        }
        schemas
    }
    fn get_props(schema: &Schema) -> HashMap<String, SchemaRef> {
        if let Some(props) = schema.properties.clone() {
            props
        } else {
            HashMap::new()
        }
    }
    fn get_min_max(schema: &Schema, tp: &str) -> (Option<i64>, Option<i64>) {
        match tp.to_lowercase().as_str() {
            "string" => {
                let min = if schema.min_length.is_none() {
                    Some(0)
                } else {
                    schema.min_length
                };
                (min, schema.max_length)
            }
            "number" | "integer" => (schema.minimum, schema.maximum),
            "array" => {
                let min = if schema.min_items.is_none() {
                    Some(0)
                } else {
                    schema.min_items
                };
                (min, schema.max_items)
            }
            "object" => {
                let min = if schema.min_properties.is_none() {
                    Some(0)
                } else {
                    schema.min_properties
                };
                (min, schema.max_properties)
            }
            _ => (Some(0), Some(0)),
        }
    }
    fn get_name_s_ref(s_ref: &SchemaRef, value: &Value, name: &Option<String>) -> String {
        let schema = s_ref.inner(value);
        if let Some(ref t) = schema.title {
            t.to_string()
        } else if let SchemaRef::Ref(r) = s_ref {
            r.param_ref.split('/').last().unwrap().to_string()
        } else if let Some(n) = name {
            n.to_string()
        } else {
            String::new()
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn get_params_rec(
        params: &mut HashMap<ParamForTableKey, ParamForTableValue>,
        schema_ref: SchemaRef,
        path: String,
        parent: Option<String>,
        dm: QuePay,
        status: Option<String>,
        name_f: Option<String>,
        value: &Value,
    ) {
        let mut children = vec![];
        let schema = schema_ref.inner(value);
        let name = Self::get_name_s_ref(&schema_ref, value, &name_f);
        for s in Self::get_all_possible_schemas(&schema) {
            let n = Self::get_name_s_ref(&schema_ref, value, &name_f);
            children.push(n.clone());
            Self::get_params_rec(
                params,
                s,
                path.clone(),
                Some(name.clone()),
                dm,
                status.clone(),
                Some(n),
                value,
            );
        }
        for (n, prop) in Self::get_props(&schema) {
            children.push(n.clone());
            Self::get_params_rec(
                params,
                prop,
                path.clone(),
                Some(name.clone()),
                dm,
                status.clone(),
                Some(n),
                value,
            );
        }
        let tp = if let Some(ref tp) = schema.schema_type {
            tp.to_string()
        } else {
            String::from("object")
        };
        let key = ParamForTableKey {
            name,
            param_type: tp.clone(),
        };
        let val = params
            .entry(key)
            .or_insert_with(ParamForTableValue::default);
        val.eps.insert(path);
        val.dms.insert(dm);
        if let Some(st) = status {
            val.statuses.insert(st);
        }
        if let Some(p) = parent {
            val.parents.insert(p);
        }
        val.children.extend(children);
        let (min, max) = Self::get_min_max(&schema, &tp);
        if let Some(m) = min {
            if m > val.min.unwrap_or(i64::MIN) {
                val.min = min;
            }
        }
        if let Some(m) = max {
            if m < val.max.unwrap_or(i64::MAX) {
                val.max = max;
            }
        }
    }
    pub fn get_params<T>(oas: &T, value: &Value) -> Vec<ParamForTable>
    where
        T: OAS,
    {
        let mut params: HashMap<ParamForTableKey, ParamForTableValue> = HashMap::new();
        for (path, item) in oas.get_paths() {
            for (_, op) in item.get_ops() {
                if let Some(b) = &op.request_body {
                    for (_, m_t) in b.inner(value).content {
                        if let Some(schema) = m_t.schema {
                            Self::get_params_rec(
                                &mut params,
                                schema,
                                path.clone(),
                                None,
                                QuePay::Payload,
                                None,
                                None,
                                value,
                            );
                        }
                    }
                }
                for (status, payload) in op.responses() {
                    if let Some(c) = payload.inner(value).content {
                        for (_, m_t) in c {
                            if let Some(schema) = m_t.schema {
                                Self::get_params_rec(
                                    &mut params,
                                    schema,
                                    path.clone(),
                                    None,
                                    QuePay::Response,
                                    Some(status.clone()),
                                    None,
                                    value,
                                );
                            }
                        }
                    }
                }
                let params1 = if let Some(p) = &op.parameters {
                    p.to_vec()
                } else {
                    vec![]
                };
                for param in params1 {
                    let param = param.inner(value);
                    if let Some(schema) = param.schema.clone() {
                        Self::get_params_rec(
                            &mut params,
                            schema,
                            path.clone(),
                            None,
                            param.from(),
                            None,
                            Some(param.name),
                            value,
                        );
                    }
                }
            }
            let params1 = if let Some(p) = item.parameters {
                p
            } else {
                vec![]
            };
            for param in params1 {
                let param = param.inner(value);
                if let Some(schema) = param.schema.clone() {
                    Self::get_params_rec(
                        &mut params,
                        schema,
                        path.clone(),
                        None,
                        param.from(),
                        None,
                        Some(param.name),
                        value,
                    );
                }
            }
        }
        ParamForTable::from_hash(params)
    }
}
