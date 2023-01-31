use super::legacy_oas::*;
use super::refs::*;
use super::schema::*;
use super::utils::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub param_in: String,
    pub description: Option<String>,
    pub required: Option<bool>,
    pub deprecated: Option<bool>,
    #[serde(rename = "allowEmptyValue")]
    pub allow_empty_value: Option<bool>,
    //Any
    pub example: Option<Value>,
    pub examples: Option<Examples>,
    pub style: Option<String>,
    pub explode: Option<bool>,
    #[serde(rename = "allowReserved")]
    pub allow_reserved: Option<bool>,
    pub schema: Option<SchemaRef>,
}
impl Parameter {
    pub fn from(&self) -> QuePay {
        match self.param_in.to_lowercase().as_str() {
            "query" => QuePay::Query,
            "header" => QuePay::Headers,
            "path" => QuePay::Path,
            "cookie" => QuePay::Headers,
            _ => QuePay::None,
        }
    }
    pub fn name(&self) -> String {
        self.name.clone()
    }
    pub fn required(&self) -> bool {
        if let Some(r) = self.required {
            r
        } else {
            false
        }
    }
    pub fn schema(&self) -> SchemaRef {
        if let Some(s) = self.schema.clone() {
            s
        } else {
            SchemaRef::default()
        }
    }
    pub fn to_desc(&self) -> ParamDescriptor {
        ParamDescriptor {
            name: self.name.clone(),
            from: self.from(),
            value: ValueDescriptor::default(),
        }
    }
}
pub type ParamEnum /*<T>*/ = Vec<Option<SchemaStrInt>>;
/*
fn parse_enum_to_int(e:&ParamEnum<String>)->ParamEnum<i64>{
    let mut v = vec![];
    for p in e{
        if let Some(pp) = p{
            v.push(Some(pp.parse::<i64>().unwrap()));
        }else{
            v.push(None);
        }
    }
    v
}*/
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ParamInt {
    min: Option<f64>,
    max: Option<f64>,
    multiple_of: i64,
    pub p_enum: Option<ParamEnum>,
    pub default: Option<SchemaStrInt>,
}
impl ParamInt {
    pub fn new(schema: &Schema) -> Self {
        ParamInt {
            min: schema.minimum,
            max: schema.maximum,
            multiple_of: if let Some(m) = schema.multiple_of {
                m
            } else {
                0
            },
            p_enum: schema.schema_enum.clone(),
            default: schema.default.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ParamString {
    min_length: i64,
    max_length: i64,
    pub p_enum: Option<ParamEnum>,
    pub default: Option<SchemaStrInt>,
}
impl ParamString {
    pub fn new(schema: &Schema) -> Self {
        ParamString {
            min_length: if let Some(m) = schema.min_length {
                m
            } else {
                0
            },
            max_length: if let Some(m) = schema.max_length {
                m
            } else {
                i64::MAX
            },
            p_enum: schema.schema_enum.clone(),
            default: schema.default.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParamValue {
    Integer(ParamInt),
    String(ParamString),
    Object,
    Array,
    Boolean,
    None,
}
impl Default for ParamValue {
    fn default() -> Self {
        Self::None
    }
}
impl ParamValue {
    pub fn from(schema: &Schema) -> Self {
        let v = if let Some(t) = schema.schema_type.clone() {
            t
        } else {
            String::new()
        };
        match v.to_lowercase().as_str() {
            "integer" => ParamValue::Integer(ParamInt::new(schema)),
            "number" => ParamValue::Integer(ParamInt::new(schema)),
            "string" => ParamValue::String(ParamString::new(schema)),
            "object" => Self::Object,
            "array" => Self::Array,
            "boolean" => Self::Boolean,
            _ => {
                /*println!("{:?}",v);*/
                Self::None
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Param {
    pub name: String,
    pub p_type: String,
    pub format: String,
    pub description: String,
    //pub properties:String,
    pub params: Vec<Param>,
    pub from: String,
    pub value: ParamValue,
    pub dm: QuePay,
    pub required: bool,
}
impl Param {
    pub fn change_prop(name: String, param: Self, from: String) -> Self {
        Param {
            name,
            p_type: param.p_type,
            format: param.format,
            description: param.description,
            //properties:param.properties,
            params: param.params,
            value: param.value,
            required: param.required,
            dm: QuePay::Payload,
            from,
        }
    }
    pub fn change_from(param: Self, from: String) -> Self {
        Param {
            name: param.name,
            p_type: param.p_type,
            format: param.format,
            description: param.description,
            //properties:param.properties,
            params: param.params,
            value: param.value,
            required: param.required,
            dm: QuePay::Payload,
            from,
        }
    }
    pub fn required(schema: &Schema, _p_type: &str, requireds: Vec<String>) -> bool {
        let name = if let Some(n) = schema.title.clone() {
            n
        } else {
            String::new()
        };
        requireds.contains(&name)
        /* match &p_type.to_lowercase().as_str(){
            "object"|"" =>,
            "boolean"|"integer"|"string"|"array"=>requireds.contains(,
        }*/
    }
    fn object_to_param(swagger: &Value, schema: Schema, p_type: String, required: bool) -> Param {
        let mut params: Vec<Param> = vec![];
        let s1 = schema.clone();
        let requireds = if let Some(r) = schema.required {
            r
        } else {
            vec![]
        };
        if let Some(items) = schema.items {
            let inner = items.inner(swagger);
            let r = Self::required(&inner, &p_type, requireds.clone());
            params.push(Param::change_from(
                Self::schema_rec(swagger, inner, r),
                String::from("items"),
            ));
        }
        if let Some(all) = schema.all_of {
            for sc in all {
                params.push(Param::change_from(
                    Self::schema_rec(swagger, sc.inner(swagger), true),
                    String::from("all"),
                ));
            }
        }
        if let Some(any) = schema.any_of {
            for sc in any {
                let r = Self::required(&sc.inner(swagger), &p_type, requireds.clone());
                params.push(Param::change_from(
                    Self::schema_rec(swagger, sc.inner(swagger), r),
                    String::from("any"),
                ));
            }
        }
        if let Some(one) = schema.one_of {
            for sc in one {
                let r = Self::required(&sc.inner(swagger), &p_type, requireds.clone());
                params.push(Param::change_from(
                    Self::schema_rec(swagger, sc.inner(swagger), r),
                    String::from("one"),
                ));
            }
        }
        if let Some(not) = schema.not {
            let r = Self::required(&s1, &p_type, requireds.clone());
            params.push(Param::change_from(
                Self::schema_rec(swagger, not.inner(swagger), r),
                String::from("not"),
            ));
        }
        if let Some(prop) = schema.properties {
            for (p_name, p) in prop {
                let r = Self::required(&p.inner(swagger), &p_type, requireds.clone());
                params.push(Param::change_prop(
                    p_name,
                    Self::schema_rec(swagger, p.inner(swagger), r),
                    String::from("prop"),
                ));
            }
        }
        let name = if let Some(n) = schema.title {
            n
        } else {
            String::new()
        };
        let description = if let Some(d) = schema.description {
            d
        } else {
            String::new()
        };
        let format = if let Some(f) = schema.format {
            println!("{f}");
            f
        } else {
            String::new()
        };
        Param {
            name,
            description,
            p_type,
            format,
            params,
            from: String::new(),
            value: ParamValue::from(&s1),
            required,
            dm: QuePay::Payload,
        }
    }
    fn simple_to_param(schema: Schema, p_type: String, required: bool) -> Self {
        let s1 = schema.clone();
        let name = if let Some(n) = schema.title {
            n
        } else {
            String::new()
        };
        let description = if let Some(d) = schema.description {
            d
        } else {
            String::new()
        };
        let format = if let Some(f) = schema.format {
            f
        } else {
            String::new()
        };
        Param {
            name,
            description,
            p_type,
            format,
            params: vec![],
            from: String::new(),
            value: ParamValue::from(&s1),
            required,
            dm: QuePay::Payload,
        }
    }
    pub fn schema_rec(swagger: &Value, schema: Schema, required: bool) -> Self {
        let p_type = if let Some(t) = schema.schema_type.clone() {
            t
        } else {
            String::new()
        };
        match p_type.to_lowercase().as_str() {
            "array" | "" | "object" => Self::object_to_param(swagger, schema, p_type, required),
            "number" | "boolean" | "integer" | "string" => {
                Self::simple_to_param(schema, String::from("string"), required)
            }
            _ => {
                println!("{p_type:?}");
                Param::default()
            }
        }
    }
    pub fn schema_to_params(
        swagger: &Value,
        schema: SchemaRef,
        name: String,
        required: bool,
    ) -> Self {
        let mut params: Vec<Param> = vec![];
        let mut schemas: Vec<Schema> = vec![];
        let sc = schema.inner(swagger);
        if let Some(all) = sc.all_of {
            schemas.extend(
                all.iter()
                    .map(|s| s.inner(swagger))
                    .collect::<Vec<Schema>>(),
            );
        }
        if let Some(any) = sc.any_of {
            schemas.extend(
                any.iter()
                    .map(|s| s.inner(swagger))
                    .collect::<Vec<Schema>>(),
            );
        }
        if let Some(one) = sc.one_of {
            schemas.extend(
                one.iter()
                    .map(|s| s.inner(swagger))
                    .collect::<Vec<Schema>>(),
            );
        }
        if let Some(not) = sc.not {
            schemas.push(not.inner(swagger));
        }
        if let Some(props) = sc.properties {
            for (_, p) in props {
                schemas.push(p.inner(swagger));
            }
        }
        for schema in schemas {
            let p_type = if let Some(t) = schema.schema_type.clone() {
                t
            } else {
                String::new()
            };
            let requireds = if let Some(r) = schema.required.clone() {
                r
            } else {
                vec![]
            };
            let r = Self::required(&schema, &p_type, requireds);
            params.push(Self::schema_rec(swagger, schema.clone(), r));
        }
        Param {
            name,
            params,
            required,
            dm: QuePay::Payload,
            ..Param::default()
        }
    }
}
