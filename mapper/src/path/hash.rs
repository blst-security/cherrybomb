use super::*;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Part{
    Number(HashMap<String,u32>),
    Uuid,
    Bool,
    String(HashMap<String,u32>),
}
impl Default for Part{
    fn default() -> Self {
        Self::String(HashMap::new())
    }
}
impl std::fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self{
            Part::Number(_)=>write!(f, "number"),
            Part::Uuid=>write!(f, "uuid"),
            Part::Bool=>write!(f, "boolean"),
            Part::String(_)=>write!(f, "string"),
        }
    }
}
impl Part{
    pub fn compare(&self,other:Self)->bool{
        matches!((self,other), (Part::String(_),Part::String(_)) | (Part::Number(_),Part::Number(_)) | (Part::Uuid,Part::Uuid))
    }
    pub fn cmp_join(self,other:Self)->Option<Self>{
        match (self.clone(),other){
            (Part::String(hm1),Part::String(hm2))=>{
                Some(Part::String(hm1.into_iter().chain(hm2).collect()))
            },
            (Part::Number(hm1),Part::Number(hm2))=>{
                Some(Part::Number(hm1.into_iter().chain(hm2).collect()))
            },
            (Part::Uuid,Part::Uuid)=>Some(self),
            _=>None,
        }
    }
    pub fn add_from_str(&mut self,part:&str){
        match self{
            Self::Number(hs_n)=>if part.parse::<i64>().is_ok(){ 
                let c = hs_n.entry(part.to_string()).or_insert(0); 
                *c+=1;
            }
            Self::String(hs_s)=> {
                let c = hs_s.entry(part.to_string()).or_insert(0); 
                *c+=1;
            },
            _=>(),
        }
    }
    pub fn part_from_str(part:&str)->Self{
        match Uuid::parse_str(part){
             Ok(_)=>Part::Uuid,
             Err(_)=>{
                if part.parse::<bool>().is_ok(){
                    Part::Bool
                }else{
                    let mut hash = HashMap::new();
                    hash.insert(part.to_string(),1);
                    match part.parse::<i64>(){
                        Ok(_)=> Part::Number(hash),
                        Err(_)=>Part::String(hash),
                    }
                }
             }
        }
    }
    pub fn add_from_part(&mut self,other:Part){
        match (self,other){
            (Part::Number(n1),Part::Number(n2))=>{
                for (k2,v2) in n2{
                    let v1 = n1.entry(k2).or_insert(0);
                    *v1+=v2;
                }
            },
            (Part::String(s1),Part::String(s2))=>{
                for (k2,v2) in s2{
                    let v1 = s1.entry(k2).or_insert(0);
                    *v1+=v2;
                }
            }
            _=>(),
        }
    }
}
/*
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathMod{
    string:String,
    parts:Vec<Part>,
}
impl PathMod{
    pub fn new(path:String)->Self{
        let split = path.split('/');
        let parts:Vec<Part> = split.clone().map(Part::from_str).collect();
        let mut i:i16 = -1;
        let mut c = 0;
        let string:String= split.map(|p| {
            i+=1;
            match parts[i as usize]{
                Part::String(_)=>{
                    if !p.is_empty(){
                        format!("/{}",p)
                    }else{
                        p.to_string()
                    }
                },
                _=>{
                    c+=1;
                    format!("/blst_param_{}",c)
                },
            }
        }).collect();
        PathMod{string,parts}
    }
    pub fn add(&mut self,path:String){
        for (p,part) in path.split('/').zip(self.parts.iter_mut()){
            part.add_from_str(p);
        }
    }
}

//pub type PathHash = HashMap<String,u32>;
//pub type PathMods = Vec<PathMod>;
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathHash{
    hash:HashMap<String,u32>,
    mods:Vec<PathMod>
}
impl PathHash{
    pub fn build_paths(paths:Vec<String>)->Self{
        let mut hash = HashMap::new(); 
        let mut mods = vec![];
        for path in paths{
            let mod1 = PathMod::new(path.clone());
            if let Some(pos) = mods.iter().position(|p:&PathMod| p.string==mod1.string){
                mods[pos].add(path.clone());
            }else{
                mods.push(mod1.clone());
            }
            let h = hash.entry(mod1.string).or_insert(0); 
            *h+=1;
        }
        PathHash{hash,mods}
    }
    pub fn add_paths(&mut self,paths:Vec<String>){
        for path in paths{
            let mod1 = PathMod::new(path.clone());
            if let Some(pos) = self.mods.iter().position(|p:&PathMod| p.string==mod1.string){
                self.mods[pos].add(path.clone());
            }else{
                self.mods.push(mod1.clone());
            }
            let h = self.hash.entry(mod1.string).or_insert(0); 
            *h+=1;
        } 
    }
    fn compare_paths(path:Vec<Part>,other:Vec<Part>)->bool{
        if path.len() == other.len(){
            for (part,o_part) in path.iter().zip(other.iter()){
                match (part,o_part){
                    (Part::String(_),Part::String(_))=>(),
                    (Part::Number(_),Part::Number(_))=>(),
                    (Part::Uuid,Part::Uuid)=>(),
                    _=>{return false;},
                }
            }
            true
        }else{
            false
        }
    }
                //if !p.starts_with("blst_param_") && !prev.is_empty(){
    fn cross_compare_paths(path:&str,other:&str)->Option<PathMod>{
        let split:Vec<&str> = path.split('/').collect();
        let other_split:Vec<&str> = other.split('/').collect();
        let mut new_path = String::from("");
        let mut new_parts = vec![];
        if split.len()==other_split.len(){
            let mut prev = split.get(0).unwrap();
            let mut o_prev = other_split.get(0).unwrap();
            for (s,o_s) in split.iter().zip(&other_split){
                println!("{:?} ,{:?} ,{:?} ,{:?} ",s,o_s,prev,o_prev);
                if s != o_s && prev==o_prev && !prev.is_empty(){
                    if let Some(new_p) = Part::from_str(s).cmp_join(Part::from_str(o_s)){ 
                        new_parts.push(new_p);
                        new_path.push_str(&format!("/blst_param_{}",prev));
                    }else{
                        return None;
                    }
                }else if s != o_s{
                    return None;
                }else if s==o_s && !s.is_empty(){
                    new_path.push_str(&format!("/{}",s));
                    prev = s;
                    o_prev = o_s;
                }
            }
            Some(PathMod{string:new_path,parts:new_parts})
        }else{
            None
        }
    }
    pub fn rerun(/*v_s:Vec<String>*/&self)->HashMap<String,Vec<Part>> {
        let mut strings_hash:HashMap<String,Vec<Part>> = HashMap::new();
        for (path,_amount) in self.hash.iter(){
        //for path in v_s.iter(){
            let mut found = false;
            for (h_path,h_parts) in strings_hash.iter_mut(){
                println!("{:?} , {:?} , {:?}",path,h_path,Self::cross_compare_paths(path,h_path));
                if let Some(mod1) = Self::cross_compare_paths(path,h_path){
                    found = true;
                    *h_parts = mod1.parts;
                }
            }
            if !found{
                let in1 = PathMod::new(path.to_string());
                strings_hash.insert(in1.string,in1.parts);
            }
        }
        strings_hash
    }
    pub fn rerun_mut(&mut self){

    }
}*/
pub fn first_cycle_single(path:String)->(String,Vec<String>){
    let mut prev = String::new();
    let mut params = vec![];
        let new_path = path.split('/').map(|part|{
            if !prev.is_empty(){
                let p = format!("blst_param_{}",prev);
                prev= part.to_string();
                match Uuid::parse_str(part){
                    Ok(_)=>{
                        params.push(part.to_string());
                        p
                    },
                    Err(_)=>{
                        if part.parse::<bool>().is_ok(){
                            params.push(part.to_string());
                            p
                        }else{
                            match part.parse::<i64>(){
                                Ok(_)=>{
                                    params.push(part.to_string());
                                    p
                                },
                                Err(_)=>part.to_string(),
                            }
                        }
                    }
                }
            }else{
                prev= part.to_string();
                part.to_string()
            }
        }).collect::<Vec<String>>().join("/");
    (new_path,params)
}
pub fn first_cycle(paths_pre:Vec<String>)->HashMap<String,(Vec<HashSet<String>>,u32)>{
    let mut paths = HashMap::new();
    for path in paths_pre{
        let (new_path,params) = first_cycle_single(path);
        let (val1,val2) = paths.entry(new_path).or_insert((vec![],0)); 
        if val1.is_empty(){
            *val1 = params.iter().map(|param|{HashSet::from([param.to_string()])}).collect();
        }else{
            for (param,val) in params.iter().zip(val1){
                val.insert(param.to_string());
            }
        }
        *val2 +=1;
    }
    paths
}
pub fn second_cycle(paths:HashMap<String,(Vec<HashSet<String>>,u32)>)->Vec<Path>{
    let mut vec1 = vec![];
    //let paths_h = paths.keys();
    for (path,(vals,_amount)) in paths.iter(){
        let mut names = vec![];
        let path_ext = path.split('/').map(|part|{
            if part.contains("blst_param_"){
                names.push(part.to_string());
                let mut p = part.replace("blst_param_","{");
                p.push('}');
                p
            }else{
                part.to_string()
            }
        }).collect::<Vec<String>>().join("/");
        let params = vals.iter().enumerate().map(|(i,v)|{
            let name =names[i].to_string().replace("blst_param_","");
            ParamDescriptor{
                from:QuePay::Path,
                name,
                value:search_for_patterns(v.iter().collect())
            }
        }).collect();
        let params = PayloadDescriptor{params};
        vec1.push(
            Path{
                path_ext,
                params,
            }); 
    }
    vec1
}





        /*
        //let paths:Vec<&String> = self.hash.keys().collect();
        //let mut hash_paths:HashMap<String,Vec<Part>> = HashMap::new();
        let mut compared:Vec<Vec<Part>> = vec![];
        for i in 0..self.hash.len(){
            if let Some(pos) = compared.iter().position(|parts| Self::compare_paths(self.mods[i].parts.clone(),parts.to_vec())){
                for (j,part) in compared[pos].iter_mut().enumerate(){
                    part.add_from_part(self.mods[i].parts[j].clone());
                }
            }else{
                compared.push(self.mods[i].parts.clone());
            }
        }
        let mut has_a_string = false;
        for c in compared{
            for part in c{
                match part{
                    Part::String(s_h)=>{
                        //if b  
                    },
                    _=>(),
                }
            }
        }
        self.clone()
    }*/
