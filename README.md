<div align="center">
  <img src="https://www.blstsecurity.com/assets/images/cli/logo.png" alt="BLST's Firecracker logo"/>
</div>

[![Maintained by blstsecurity](https://img.shields.io/badge/maintained%20by-blst%20security-4F46E5)](https://www.blstsecurity.com/) [![docs](https://img.shields.io/badge/docs-passing-brightgreen)](https://www.blstsecurity.com/firecracker/Documentation) [![slack-community](https://img.shields.io/badge/Slack-4A154B?style=plastic&logo=slack&logoColor=white)](blst-aaaae62s6fjuna7g2jn4z5zrqq@blst-workspace.slack.com)

# Who is BLST and what do we do?
[BLST](https://www.blstsecurity.com/) (Business Logic Security Testing) is a startup company that's developing an automatic penetration tester, replacing the manual penetration tester by using an advanced neural network and helping developers build more secure applications by catching bugs before they hit production.
# What is BLST's Firecracker?
BLST's Firecracker is meant to be a **free version** of our main SaaS product.
It's an easy to use CLI that scans your APIs for invalid business logic flows.
# What exactly is "Business Logic"?
Business logic is the part of an application that contains all of the rules and procedures related to how data is created, stored, and changed. It is used when describing computer applications like databases and websites. If you don't write the business logic correctly, your database or website may not work properly -- thus making it vulnerable.
One of the most common root causes of business logic vulnerabilities is making flawed assumptions and blindingly trusting user behavior or input.
## How does this CLI differs from our SaaS product?
Main differences are the cut-down [Decider](#features) algorithm, lack of CI/CD integration and no management dashboard.
We made it so you can easily download, install and run it on your local machine to get a better understanding of what our main product is capable of.
[Learn more about us and what we can do for your business](https://www.blstsecurity.com/)
# Features
- **Mapper** - takes in traffic logs and maps the business logic flow of the application, outputs a digest file.
- **Decider** - takes in traffic logs and decides whether a certain business logic flow is an anomaly or not.
- **Attacker** - takes in the digest file from the mapper and "attacks" the API while using the Decider to determine whether something is an anomaly or not.
- **Visualizer** - takes in the digest file from the mapper and visualizes the business logic flow of the application.
[Use the JSON you get from the CLI and put it here to visualize your network now!](https://www.blstsecurity.com/firecracker/Visualizer)
# Installation
### Clone the repository
Firecracker can be installed by cloning our git repository and building it with cargo.
Note that you must have Rust installed on your machine (see [Direct download](#direct-download) to avoid this step).
```
git clone https://github.com/blst-security/firecracker
cd firecracker
cargo build --release
```
### Direct download
You can also download the binary file directly from [our website](https://www.blstsecurity.com/firecracker).
This is a binary file and you DO NOT have to install Rust.
# Usage
After installing the CLI, verify it's working by running
```
firecracker --version
```
Now, start by mapping your logs by running
```
firecracker map --file <LOGS_FILE_PATH> --output <OUTPUT_FILE_NAME>
```
### Passive checking for anomalies (1 step)
To run the decider only to **passively** check for anomalies in your logs, run
```
firecracker decide --file <LOGS_FILE_PATH> --map <MAPPED_FILE_PATH>
```
### Active attacking and checking for anomalies (2 steps)
After mapping, prepare the attacker by running the command below.
This will print the populations (API groups) so you can choose which one you want to run the attacker on.
```
firecracker prepare --url <URL_TO_ATTACK> --map <MAPPED_FILE_PATH>
```
Now you can use the attacker to **actively** attack the API by running
```
firecracker attack --map <MAPPED_FILE_PATH> (the same one you used in the prepare step) --output <OUTPUT_FILE_NAME> --population <POPULATION_NUMBER> (the one you got from the prepare step) --generations <MAX_GENERATIONS_NUMBER> --verbosity <VERBOSITY_LEVEL>
```
In the future, if you want to load new logs to an existing map file, run
```
firecracker load --file <LOGS_FILE_PATH> --map <MAPPED_FILE_PATH>
```
# Upcoming features
This product is currently under active development, and we are working on stabilizing more features.
Here's a small taste of what's coming in the future:
- **More installation options** - APT, Homebrew, crates.io, npm, Yarn etc.
- **Decider** - A more advanced algorithm that can detect more anomalies.
- **Mapper** - Path parameters analysis and support for more complex business logic flows.
- **Attacker** - Better support for more complex business logic flows.

# Support

### Documentation
Please read [our documentation](https://www.blstsecurity.com/firecracker/Documentation) to understand the format of sessions our mapper needs to function correctly.

### Get help
If you have any questions, please send us a message to [support@blstsecurity.com](mailto:support@blstsecurity.com).
You are also welcome to open an Issue here on GitHub.
# Contributing
While this is an open source project, it is meant to be as an easy to get-started with example of our SaaS project, and outside contribution is not necessary.
You can talk to us in our developers' [slack channel](https://join.slack.com/share/enQtMjcyOTUyNjY5MDQzOC0yOTNmZjMwYTc2Y2MxNjY4NTkwN2QwM2YxMmQwMzk3YTg2OWMwMWU5NjI5YzFiYjgyMjBhOTRiMmJlN2Y0ZTYw?cdn_fallback=1).
<div align="center">
  <img src="https://www.blstsecurity.com/logo193.png" alt="BLST Security's logo"/>
</div>
