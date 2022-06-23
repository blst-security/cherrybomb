use super::*;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EpForTable {
    path: String,
    //urls
    servers: Vec<String>,
    ops: Vec<Method>,
    query_params: Vec<String>,
    headers_params: Vec<String>,
    req_body_params: Vec<String>,
    res_params: Vec<String>,
    statuses: Vec<String>,
}
impl fmt::Display for EpForTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut string = String::new();
        let lines = *([
            self.statuses.len(),
            self.ops.len(),
            self.query_params.len(),
            self.req_body_params.len(),
            self.headers_params.len(),
            self.res_params.len(),
        ]
        .iter()
        .max()
        .unwrap_or(&0));
        let h_p = vv(&self.headers_params, 0);
        let h_p = &h_p[0..*([h_p.len(), 25].iter().min().unwrap_or(&0))];
        let q_p = vv(&self.query_params, 0);
        let q_p = &q_p[0..*([q_p.len(), 25].iter().min().unwrap_or(&0))];
        let r_b_p = vv(&self.req_body_params, 0);
        let r_b_p = &r_b_p[0..*([r_b_p.len(), 25].iter().min().unwrap_or(&0))];
        let r_p = vv(&self.res_params, 0);
        let r_p = &r_p[0..*([r_p.len(), 25].iter().min().unwrap_or(&0))];
        string.push_str(&format!(
            "{:75}|{:7}|{:25}|{:25}|{:25}|{:25}|{:8}\n",
            &self.path.bold().bright_cyan(),
            vv(&self.ops, 0),
            q_p,
            h_p,
            r_b_p,
            r_p,
            color_status(&vv(&self.statuses, 0))
        ));
        for i in 1..lines {
            let h_p = vv(&self.headers_params, i);
            let h_p = &h_p[0..*([h_p.len(), 25].iter().min().unwrap_or(&0))];
            let q_p = vv(&self.query_params, i);
            let q_p = &q_p[0..*([q_p.len(), 25].iter().min().unwrap_or(&0))];
            let r_b_p = vv(&self.req_body_params, i);
            let r_b_p = &r_b_p[0..*([r_b_p.len(), 25].iter().min().unwrap_or(&0))];
            let r_p = vv(&self.res_params, i);
            let r_p = &r_p[0..*([r_p.len(), 25].iter().min().unwrap_or(&0))];
            string.push_str(&format!(
                "{:75}|{:7}|{:25}|{:25}|{:25}|{:25}|{:8}\n",
                "",
                vv(&self.ops, i),
                q_p,
                h_p,
                r_b_p,
                r_p,
                color_status(&vv(&self.statuses, i))
            ));
        }
        string.push_str(&format!("{:-<200}\n", ""));
        write!(f, "{}", string)
    }
}
impl EpForTable {
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
    fn get_name_s_ref(s_ref: &SchemaRef, value: &Value, name: Option<&String>) -> String {
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
    fn schema_rec(
        params: &mut HashSet<String>,
        schema_ref: &SchemaRef,
        value: &Value,
        name_f: Option<&String>,
    ) {
        let schema = schema_ref.inner(value);
        for s in Self::get_all_possible_schemas(&schema) {
            let n = Self::get_name_s_ref(schema_ref, value, name_f);
            Self::schema_rec(params, &s, value, Some(&n));
            params.insert(n);
        }
        for (n, prop) in Self::get_props(&schema) {
            Self::schema_rec(params, &prop, value, Some(&n));
            params.insert(n);
        }
    }
    pub fn from_oas_path(path: &str, item: &PathItem, value: &Value) -> Self {
        let ops1 = item.get_ops();
        //,req_body_params,res_params
        let (mut query_params, mut headers_params, mut req_body_params, mut res_params): (
            Vec<String>,
            Vec<String>,
            Vec<String>,
            Vec<String>,
        ) = (vec![], vec![], vec![], vec![]);
        for (_, op) in ops1.iter() {
            let q: Vec<String> = op
                .params()
                .iter()
                .filter_map(|param| {
                    let param = param.inner(value);
                    match param.from() {
                        QuePay::Query => Some(param.name),
                        _ => None,
                    }
                })
                .collect();
            let h: Vec<String> = op
                .params()
                .iter()
                .filter_map(|param| {
                    let param = param.inner(value);
                    match param.from() {
                        QuePay::Headers => Some(param.name),
                        _ => None,
                    }
                })
                .collect();
            let req: Vec<String> = if let Some(b) = &op.request_body {
                let mut params = HashSet::new();
                for m_t in b.inner(value).content.values() {
                    if let Some(schema) = &m_t.schema {
                        Self::schema_rec(&mut params, schema, value, None);
                    }
                }
                params.iter().cloned().collect::<Vec<String>>()
            } else {
                vec![]
            };
            let res: Vec<String> = op
                .responses()
                .iter()
                .flat_map(|(_, payload)| {
                    let mut params = HashSet::new();
                    if let Some(c) = &payload.inner(value).content {
                        for m_t in c.values() {
                            if let Some(schema) = &m_t.schema {
                                Self::schema_rec(&mut params, schema, value, None);
                            }
                        }
                    }
                    params.iter().cloned().collect::<Vec<String>>()
                })
                .collect();
            query_params.extend(q);
            headers_params.extend(h);
            req_body_params.extend(req);
            res_params.extend(res);
        }
        EpForTable {
            path: path.to_string(),
            servers: item
                .servers
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|s| s.url.clone())
                .collect(),
            ops: ops1.iter().map(|(m, _)| m).cloned().collect(),
            query_params,
            headers_params,
            statuses: ops1
                .iter()
                .flat_map(|(_, op)| {
                    op.responses
                        .as_ref()
                        .unwrap_or(&HashMap::new())
                        .iter()
                        .map(|(s, _)| s)
                        .cloned()
                        .collect::<Vec<String>>()
                })
                .collect(),
            res_params,
            req_body_params,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EpTable {
    pub eps: Vec<EpForTable>,
    servers: Vec<String>,
}
impl EpTable {
    pub fn print(&self) {
        let head = format!(
            "{:75}|{:7}|{:25}|{:25}|{:25}|{:25}|{:8}",
            "PATH".bold().underline(),
            "METHODS".bold().underline(),
            "QUERY PARAMS".bold().underline(),
            "HEADER PARAMS".bold().underline(),
            "BODY_PARAMS".bold().underline(),
            "RESPONSE PARAMS".bold().underline(),
            "STATUSES".bold().underline()
        );
        for (i, ep) in self.eps.iter().enumerate() {
            if i % 50usize == 0 {
                println!("{}\n{:-<190}", head, "");
            }
            print!("{}", ep);
        }
    }
    pub fn path_only(&self, path: &str) -> Self {
        let eps = self
            .eps
            .iter()
            .filter(|p| p.path.as_str() == path)
            .cloned()
            .collect::<Vec<EpForTable>>();
        EpTable {
            servers: self.servers.clone(),
            eps,
        }
    }
    pub fn new<T>(value: &Value) -> Self
    where
        T: OAS + Clone + Serialize + for<'de> serde::Deserialize<'de>,
    {
        let oas = serde_json::from_value::<T>(value.clone()).unwrap();
        let eps: Vec<EpForTable> = oas
            .get_paths()
            .iter()
            .map(|(path, item)| EpForTable::from_oas_path(path, item, value))
            .collect();
        EpTable {
            eps,
            servers: oas
                .servers()
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|s| s.url.clone())
                .collect(),
        }
    }
}
