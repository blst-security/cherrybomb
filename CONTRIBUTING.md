# Contributing to Cherrybomb

While this is an open source project, it is meant to be as an easy to get-started with example of our SaaS project, and outside contribution is not necessary.
The main area in which we are currently looking for contribution is the [swagger](#developing-new-checks-to-the-swagger).

## Developing new checks to the Swagger

Please take a note of this few things before contributing:
1. Make sure that you are familiar with the structure of a [Swagger Specification](https://swagger.io/specification/).
2. We are looking for contribution of passive checks that are searching for stuff that are not on par with the specification.
3. We have already implemented a swagger interface that can read and destructure the inputted file (a few swagger files for example are available in the [examples folder](https://github.com/blst-security/cherrybomb/swagger/examples)).

### Developing

Please note that you are going to need [Rust](https://www.rust-lang.org/tools/install) installed on your computer.

The development branch is `canary`. This is the branch that all pull requests should be made against.

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

First, you're going to need to navigate to src/scan/checks.rs and scroll down until you see the following macro implementation:
```
impl_passive_checks![
  ...
]
```

![image](https://user-images.githubusercontent.com/12970637/150996600-616ab21f-8816-42af-b87e-2c5023a99b15.png)

Now add your new check to the bottom of the array, in this example we added the following check:
```
(CheckValidResponses, check_valid_responses, "VALID RESPONSES", "Checks for valid responses codes")
```

![image](https://user-images.githubusercontent.com/12970637/150996957-ba161b42-de61-4b96-bcf2-dbb9e7e563ec.png)

Please note that each check is a tuple that consists of:
* The name of the the check, in CamelCase.
* The name of the function you're going to implement, in snake_case.
* The name of the check as it's going to appear in the output table, in CAPS.
* The description of the check as it's going to appear in the output table, in plain English.

Now, navigate to src/scan/passive/additional_checks.rs and scroll down until you see the following implementation:

```
impl PassiveSwaggerScan {
  ...
}
```

Now, at the bottom of this impl block, create a new public function with the exact name as you wrote it in the previous step.
In this example we added the following function:

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
4. The function should return a vector of Alerts.
5. In the next step, don't forget to add alerts to the vector.

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

That's it!
Thank you for your contribution!
