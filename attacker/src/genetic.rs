use super::*;
use rand::Rng;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Population {
    endpoints: Vec<String>,
    generation: u16,
    max_members: u16,
    min_members: u16,
    top_score: u16,
    genomes: Vec<Genome>,
    gene_pool: HashSet<Gene>,
    top_genes: HashMap<String, HashSet<Gene>>,
    top_genomes: Vec<Genome>,
    cross_rate: u8,
    mutation_rate: u8,
    fitness_score: u64,
    mutations_acc: u64,
    fixation: u8,
}
impl Default for Population {
    fn default() -> Self {
        Population {
            generation: 0,
            max_members: 400,
            min_members: 50,
            top_score: u16::MAX,
            genomes: vec![],
            gene_pool: HashSet::new(),
            top_genes: HashMap::new(),
            top_genomes: vec![],
            mutation_rate: 20,
            cross_rate: 10,
            fitness_score: 0,
            endpoints: vec![],
            mutations_acc: 0,
            fixation: 0,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub enum Verbosity {
    Verbose,
    Default,
    Basic,
    None,
}
const TOP: u8 = 25;
#[allow(dead_code)]
impl Population {
    pub fn new(
        group: &Group,
        max_members: u16,
        min_members: u16,
        top_score: Option<u16>,
        mutation_rate: u8,
        cross_rate: u8,
    ) -> Population {
        let top_score = if let Some(s) = top_score { s } else { u16::MAX };
        let genomes = (0..min_members)
            .map(|_i| Genome::new(&group.endpoints))
            .collect::<Vec<Genome>>();
        let mut gene_pool = HashSet::new();
        for genome in genomes.iter() {
            genome.genes().iter().for_each(|gene| {
                gene_pool.insert(gene.clone());
            });
        }
        let mut top_genes = HashMap::new();
        let endpoints: Vec<String> = group
            .endpoints
            .iter()
            .map(|ep| ep.path.path_ext.clone())
            .collect();
        for ep in &endpoints {
            top_genes.insert(ep.clone(), HashSet::new());
        }
        Population {
            generation: 0,
            max_members,
            min_members,
            top_score,
            genomes,
            gene_pool,
            top_genes,
            top_genomes: vec![],
            mutation_rate,
            cross_rate,
            fitness_score: 0,
            endpoints,
            mutations_acc: 0,
            fixation: 0,
        }
    }
    pub fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
    fn print(&self, verbosity: Verbosity) {
        match verbosity {
            Verbosity::Verbose => {
                let cs = self.genomes[0]
                    .genes()
                    .iter()
                    .map(|g| g.chromosomes().len() as u8)
                    .collect::<Vec<u8>>();
                let fs = self
                    .top_genomes
                    .iter()
                    .map(|g| g.fitness())
                    .collect::<Vec<u16>>();
                let print = format!(
                    "group:{:?}
generation:{}
population size:{}
genes in genomes:{}
number of chromosomes for each gene:{:?}
fitness score:{}
top genomes fitness:{:?}
mutations accumelated:{}
fixation level:{}
",
                    self.endpoints,
                    self.generation,
                    self.genomes.len(),
                    self.genomes[0].genes().len(),
                    cs,
                    self.fitness_score,
                    fs,
                    self.mutations_acc,
                    self.fixation
                );
                println!("{}", print);
            }
            Verbosity::Default => {
                let cs = self.genomes[0]
                    .genes()
                    .iter()
                    .map(|g| g.chromosomes().len() as u8)
                    .collect::<Vec<u8>>();
                let print = format!(
                    "group:{:?}
generation:{}
population size:{}
genes in genomes:{}
number of chromosomes for each gene:{:?}
fitness score:{}
",
                    self.endpoints,
                    self.generation,
                    self.genomes.len(),
                    self.genomes[0].genes().len(),
                    cs,
                    self.fitness_score
                );
                println!("{}", print);
            }
            Verbosity::Basic => {
                let print = format!(
                    "group:{:?}
generation:{}
population size:{}
fitness score:{}
",
                    self.endpoints,
                    self.generation,
                    self.genomes.len(),
                    self.fitness_score
                );
                println!("{}", print);
            }
            Verbosity::None => {
                let print = format!(
                    "group:{:?}
generation:{}
fitness score:{}
",
                    self.endpoints, self.generation, self.fitness_score
                );
                println!("{}", print);
            }
        }
    }
    pub fn refit(&mut self, anomalies: Vec<Option<Anomaly>>, anomaly_scores: Vec<Vec<u16>>) {
        self.generation += 1;
        for (i, (genome, anomaly)) in self.genomes.iter_mut().zip(anomalies).enumerate() {
            genome.refit(anomaly.is_some(), &anomaly_scores[i]);
        }
        self.update_gene_pool();
        self.select_top();
        self.build_new_generation();
    }
    fn rate_condition(rate: u8) -> bool {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..100) > rate
    }
    fn synthesize(&self) -> Vec<Gene> {
        let mut genes = vec![];
        let mut rng = rand::thread_rng();
        for val in self.top_genes.values() {
            let v = val.iter().cloned().collect::<Vec<Gene>>();
            genes.push(v[rng.gen_range(0..v.len())].clone());
        }
        genes
    }
    pub fn build_new_generation(&mut self) {
        let mut new_genomes = self.top_genomes.clone();
        for genome in &self.genomes {
            if new_genomes.len() < (self.max_members / 2).into() {
                if Self::rate_condition(self.cross_rate) {
                    //evolve returns 3 genomes
                    new_genomes.extend(genome.evolve(&self.top_genomes));
                } else if Self::rate_condition(self.mutation_rate) {
                    new_genomes.push(genome.mutate());
                }
            }
        }
        for _ in 0..(self.max_members / 4) {
            new_genomes.push(Genome::from_genes(self.synthesize()));
        }
        self.genomes = new_genomes;
    }
    pub async fn run_gen(
        &self,
        verbosity: Verbosity,
        base_url: &str,
        headers: &[Header],
        auth: &Authorization,
    ) -> Vec<Session> {
        let mut result_sessions = vec![];
        self.print(verbosity);
        for (i, genome) in self.genomes.iter().enumerate() {
            let (session, choises) = genome.run(i.to_string(), base_url, headers, auth).await;
            match verbosity {
                Verbosity::Verbose => {
                    println!("session number:{}", i);
                    let mut acc = 0;
                    for (j, rr) in session.req_res.iter().enumerate() {
                        let acc1 = genome.genes()[j].chromosomes().len();
                        println!("choises:{:?}", choises[acc..(acc + acc1)].to_vec());
                        println!("{}", rr);
                        acc += acc1;
                    }
                }
                Verbosity::Default => println!("session number:{}\nchoises:{:?}", i, choises),
                Verbosity::Basic => println!("session number:{}", i),
                Verbosity::None => (),
            }
            result_sessions.push(session);
        }
        result_sessions
    }
    fn update_gene_pool(&mut self) {
        for genome in self.genomes.iter() {
            genome.genes().iter().for_each(|gene| {
                self.gene_pool.insert(gene.clone());
            });
        }
    }
    fn select_top(&mut self) {
        self.genomes.sort_by_key(|g| g.fitness());
        let top = self
            .genomes
            .iter()
            .rev()
            .take(TOP.into())
            .cloned()
            .collect::<Vec<Genome>>();
        self.top_genomes = top;
        let mut v = self.gene_pool.iter().cloned().collect::<Vec<Gene>>();
        v.sort_by_key(|g| g.fitness());
        let top = v.iter().rev();
        let mut t_genes = HashMap::new();
        for ep in self.top_genes.keys() {
            let mut vals = HashSet::new();
            for t in top.clone() {
                if vals.len() < 10 {
                    if &t.ep == ep {
                        vals.insert(t.clone());
                    }
                } else {
                    break;
                }
            }
            t_genes.insert(ep.clone(), vals);
        }
        self.top_genes = t_genes;
    }
}
