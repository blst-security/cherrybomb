# Contributing to Cherrybomb

While this is an open source project, it is meant to be as an easy to get-started with example of our SaaS project, and outside contribution is not necessary.
The main area in which we are currently looking for contribution is the [OAS](#developing-new-checks-to-the-OAS).

## Developing new checks to the OAS

Please take a note of this few things before contributing:
1. Make sure that you are familiar with the structure of a [OpenAPI Specification](https://swagger.io/specification/).
2. We are looking for contribution of:
   - Passive checks to varify that an OAS file follows the specefication and best practices.
   - Active checks that send requests to the target API to verify the OAS file and test for common vulnerabilities.
4. We have already implemented a OAS interface that can read and destructure the inputted file (a few OAS files for example are available in the [examples folder](https://github.com/blst-security/cherrybomb/swagger/examples)).

### Developing

Please note that you are going to need [Rust](https://www.rust-lang.org/tools/install) installed on your computer.

The development branch is `dev`. This is the branch that all pull requests should be made against.

To develop locally:

1. [Fork](https://help.github.com/articles/fork-a-repo/) this repository to your
   own GitHub account and then
   [clone](https://help.github.com/articles/cloning-a-repository/) it to your local device.
2. Create a new branch:
   ```
   git checkout -b MY_BRANCH_NAME
   ```
3. Switch to the Rust Nightly channel:
   ```
   rustup default nightly
   ```
4. Make sure Rust is up-to-date:
   ```
   rustup update
   ```
Now you should be ready to start contributing.

### Developing a new check

First, you're going to need to navigate to swagger/src/scan/checks.rs and scroll down until you see the following macro implementation:

Passive:
```
impl_passive_checks![
  ...
]
```

Active:
```
impl_active_checks![
   ...
];
```


![image](https://user-images.githubusercontent.com/12970637/150996600-616ab21f-8816-42af-b87e-2c5023a99b15.png)

Now add your new check to the bottom of the array, in this example we added the following check:
```
(CheckValidResponses, check_valid_responses, "VALID RESPONSES", "Checks for valid responses codes")
```

![image](https://user-images.githubusercontent.com/12970637/150996957-ba161b42-de61-4b96-bcf2-dbb9e7e563ec.png)

Please note that each check is a tuple that consists of:

**Passive:**

* The name of the the check, in CamelCase.
* The name of the function you're going to implement, in snake_case.
* The name of the check as it's going to appear in the output table, in CAPS.
* The description of the check as it's going to appear in the output table, in plain English.

**Active:**

* The name of the the check, in CamelCase.
* The name of the function you're going to implement, in snake_case.
* The name of the function that will test the responses, in snake_case.
* The name of the check as it's going to appear in the output table, in CAPS.
* The description of the check as it's going to appear in the output table, in plain English.

Now, navigate to 
- swagger/src/scan/passive/additional_checks.rs (Passive)
- swagger/src/scan/active/additional_checks.rs (Active)
and scroll down until you see the following implementation:

Passive:
```
impl<T: OAS + Serialize> PassiveSwaggerScan<T> {
  ...
}
```

Active:
```impl<T: OAS + Serialize> ActiveScan<T> {
   ...
}
```


Now, at the bottom of this impl block, create a new public function with the exact name as you wrote it in the previous step.
In this example we added the following function:

Passive: 
```
 pub fn check_valid_responses(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = vec![];

        alerts
    }
```


![image](https://user-images.githubusercontent.com/12970637/150998909-27f068dc-884f-476d-8826-ce39673c00e1.png)

Before continuing, please take note of a few things:

1. The function should be public.
2. The function should be named exactly as you wrote it in the previous step.
3. The function should receive &self as a parameter.
5. The function should return a vector of Alerts (**Passive**) or a CheckRetVal type (**Active**).
6. In the next step, don't forget to add alerts to the vector.

The CheckRetVal type: 
```
type CheckRetVal = (Vec<(ResponseData, AttackResponse)>, AttackLog);
```

Also note the structure of each Alert:
1. The severity level of the alert (Info, Low, Medium, High, Critical).
2. Description of the alert.
3. Location of the alert (i.e the URL of the endpoint, specific operation, status code).

In this example, we added the following checks:

```
for (path, item) in &self.swagger.paths {
            for (m, op) in item.get_ops() {
                let statuses = op
                    .responses()
                    .iter()
                    .map(|(k, _v)| k.clone())
                    .collect::<Vec<String>>();
                for status in statuses {
                    if status.parse::<u16>().is_err() {
                        if status != "default" {
                            alerts.push(Alert::new(
                                Level::Low,
                                "Responses have an ivalid or unrecognized status code",
                                format!("swagger path:{} operation:{} status:{}", path, m, status),
                            ));
                        }
                    }
                }
            }
        }
```

And this is how the complete function looks like:

![image](https://user-images.githubusercontent.com/12970637/150999803-c7502c4d-4d42-4f08-af38-ae62d208fe22.png)

For the Active checks, we need to build and send requests - the responses to which are sent to the response check function that will generate the Alerts for us.

Here is an example of an active tests that sends POST requests with integer amounts above and below he specified min and max in the shcema:
```
pub async fn check_min_max(&self, auth: &Authorization ) -> CheckRetVal {
     let mut ret_val = CheckRetVal::default();
     for oas_map in self.payloads.iter() {
         for (json_path,schema) in &oas_map.payload.map {
             let test_vals = Vec::from([
                 schema.minimum.map(|min| ("minimum",min-1)),
                 schema.maximum.map(|max| ("maximum",max+1)),
             ]);
             for val in test_vals
                 .into_iter()
                 .flatten(){
                     for (m,_) in oas_map.
                     path.
                     path_item.
                     get_ops().
                     iter().
                     filter(|(m,_)|m == &Method::POST){
                         let url;
                         if let Some(servers) = &self.oas.servers(){
                             if let Some(s) = servers.first(){
                                 url = s.url.clone(); 
                             } else {continue};
                         } else {continue};
                         let req = AttackRequest::builder()
                             .uri(&url, &oas_map.path.path)
                             .method(*m)
                             .headers(vec![])
                             .parameters(vec![])
                             .auth(auth.clone())
                             //The change_payload function takes the example payload and chenges the specified path in it
                             .payload( &change_payload(&oas_map.payload.payload,json_path,json!(val.1)).to_string())
                             .build();
                         if let Ok(res) = req.send_request(true).await {
                             //logging request/response/description
                             ret_val.1.push(&req,&res,"Testing min/max values".to_string());
                             ret_val.0.push((
                                 ResponseData{
                                     location: oas_map.path.path.clone(),
                                     alert_text: format!("The {} for {} is not enforced by the server", val.0, json_path[json_path.len() - 1])
                                 },
                                 res.clone(),
                             ));
                             println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                         } else {
                             println!("REQUEST FAILED");
                         }

                     }
                 }

         }
     }
     ret_val
 }
```

That's it!
Thank you for your contribution!
