use super::*;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct Chromosome {
    pub param_name: String,
    pub dna: Vec<u8>,
    pub delivery_method: QuePay,
    pub descriptor: ValueDescriptor,
}
impl Chromosome {
    pub fn redraw_dna(&mut self) {
        let mut rng = rand::thread_rng();
        let len = self.dna.len();
        let dna = (1..len).map(|_i| rng.gen_range(0..2)).collect::<Vec<u8>>();
        self.dna = dna;
    }
    pub fn new(param: &ParamDescriptor) -> Chromosome {
        let mut rng = rand::thread_rng();
        let len = match param.value {
            ValueDescriptor::Number(_) => 16,
            ValueDescriptor::String(_) => 24,
            ValueDescriptor::Bool => 1,
            ValueDescriptor::Unknown => 42,
        };
        let dna = (0..len).map(|_i| rng.gen_range(0..2)).collect::<Vec<u8>>();
        Chromosome {
            param_name: param.name.clone(),
            dna,
            delivery_method: param.from,
            descriptor: param.value.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct Gene {
    chromosomes: Vec<Chromosome>,
    pub ep: String,
    pub method: Method,
    fitness: u16,
}
impl Gene {
    pub fn chromosomes(&self) -> &[Chromosome] {
        &self.chromosomes
    }
    pub fn fitness(&self) -> u16 {
        self.fitness
    }
    pub fn refit(&mut self, new_f: u16) {
        self.fitness = new_f;
    }
    pub fn cross(&self, other: &Gene) -> Gene {
        let mut rng = rand::thread_rng();
        let mut new_chromosomes = vec![];
        for (c, c_other) in self.chromosomes.iter().zip(&other.chromosomes) {
            //probability of 2/3 to stick with original
            if rng.gen_range(0..3) > 0 {
                new_chromosomes.push(c.clone());
            } else {
                new_chromosomes.push(c_other.clone());
            }
        }
        Gene {
            ep: self.ep.clone(),
            method: self.method,
            chromosomes: new_chromosomes,
            fitness: 0,
        }
    }
    pub fn renew(&self) -> Gene {
        let mut n = self.clone();
        for c in &mut n.chromosomes {
            c.redraw_dna();
        }
        n
    }
    pub fn new(ep: &Endpoint) -> Gene {
        let mut chromosomes = vec![];
        for param in &ep.req_res_payloads.req_payload.params {
            chromosomes.push(Chromosome::new(param));
        }
        for param in &ep.path.params.params {
            chromosomes.push(Chromosome::new(param));
        }
        for header in &ep.common_req_headers.headers {
            if let EpHeaderValue::Payload(payload) = &header.value {
                chromosomes.push(Chromosome::new(payload));
            }
        }
        Gene {
            chromosomes,
            ep: ep.path.path_ext.clone(),
            method: ep.methods.greatest().0,
            fitness: 0,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Genome {
    genes: Vec<Gene>,
    fitness: u16,
}
impl Genome {
    pub fn genes(&self) -> &[Gene] {
        &self.genes
    }
    pub fn fitness(&self) -> u16 {
        self.fitness
    }
    pub fn from_genes(genes: Vec<Gene>) -> Self {
        Genome { genes, fitness: 0 }
    }
    pub fn evolve(&self, top_genomes: &[Genome]) -> Vec<Genome> {
        let mut evolutions = vec![];
        let mut rng = rand::thread_rng();
        for _ in 0..3 {
            let mut genes = vec![];
            for (i, gene) in self.genes.iter().enumerate() {
                let index = rng.gen_range(0..top_genomes.len());
                genes.push(gene.cross(&top_genomes[index].genes[i]))
            }
            evolutions.push(Genome::from_genes(genes));
        }
        evolutions
    }
    pub fn mutate(&self) -> Genome {
        let mut rng = rand::thread_rng();
        let mut genes = vec![];
        for gene in &self.genes {
            // odds of 1/2 to stick with old
            if rng.gen_range(0..2) > 0 {
                genes.push(gene.clone());
            } else {
                genes.push(gene.renew());
            }
        }
        Genome { genes, fitness: 0 }
    }
    pub fn new(eps: &[Endpoint]) -> Genome {
        let mut genes = vec![];
        for ep in eps {
            genes.push(Gene::new(ep));
        }
        Genome { genes, fitness: 0 }
    }
    pub async fn run(
        &self,
        token: String,
        base_url: &str,
        headers: &[Header],
        auth: &Authorization,
    ) -> (Session, Vec<String>) {
        let (req_res, choises) = attack_flow(base_url, &self.genes, headers, auth).await;
        (Session { token, req_res }, choises)
    }
    pub fn refit(&mut self, anomaly: bool, anomaly_scores: &[u16]) {
        for (i, gene) in self.genes.iter_mut().enumerate() {
            gene.refit(anomaly_scores[i]);
        }
        self.fitness = self.genes.iter().map(|g| g.fitness).sum();
        if anomaly {
            self.fitness += 100;
        }
    }
}
