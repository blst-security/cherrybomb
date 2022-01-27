
struct A{

}


impl PassiveScanRule for A{
    fn scan(&self)->Vec<Alert>{
    }
}
