use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Part{
    Number(HashSet<String>),
    Uuid,
    String(HashSet<String>),
}
impl Default for Part{
    fn default() -> Self {
        Self::String(HashSet::new())
    }
}
impl Part{
    pub fn add_from_str(&mut self,part:&str){
        match self{
            Self::Number(hs_n)=>if let Ok(_) = part.parse::<i64>(){ hs_n.insert(part.to_string()); }
            Self::String(hs_s)=> {hs_s.insert(part.to_string());},
            _=>(),
        }
    }
    pub fn from_str(part:&str)->Self{
        match Uuid::parse_str(part){
             Ok(_)=>Part::Uuid,
             Err(_)=>{
                let mut hash = HashSet::new();
                hash.insert(part.to_string());
                match part.parse::<i64>(){
                    Ok(_)=> Part::Number(hash),
                    Err(_)=>Part::String(hash),
                }
             }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathMod{
    string:String,
    parts:Vec<Part>,
}
impl PathMod{
    pub fn new(path:String)->Self{
        let split = path.split("/");
        let parts:Vec<Part> = split.clone().map(|p|  Part::from_str(&p)).collect();
        let mut i:i16 = -1;
        let string:String= split.map(|p| {
            i+=1;
            match parts[i as usize]{
                Part::String(_)=>p.to_string(),
                _=>format!("param_{}",i+1),
            }
        }).collect();
        PathMod{string,parts}
    }
    pub fn add(&mut self,path:String){
        for (p,part) in path.split("/").zip(self.parts.iter_mut()){
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
    pub fn rerun(&mut self){}
}
