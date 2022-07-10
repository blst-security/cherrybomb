// use super::*;
// pub fn get_path_urls(path: &PathItem, servers: Option<Vec<Server>>) -> Vec<(Method, String)> {
//     let mut urls = vec![];
//     let methods: Vec<Method> = path.get_ops().iter().map(|(m, _)| m).cloned().collect();
//     for (m, op) in path.get_ops() {
//         if let Some(servers) = &op.servers {
//             urls.extend(
//                 servers
//                     .iter()
//                     .map(|s| (m, s.url.clone()))
//                     .collect::<Vec<(Method, String)>>(),
//             );
//         }
//     }
//     if urls.is_empty() {
//         if let Some(servers) = servers {
//             for m in methods {
//                 urls.extend(servers.iter().map(|s| (m, s.url.clone())));
//             }
//         }
//     }
//     urls
// }
