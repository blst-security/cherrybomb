<div align="center">
  
![cherry_bomb_v5_1](https://user-images.githubusercontent.com/12970637/159654379-eaff2dde-ba9c-403b-9f23-d412b4657847.png)

  <h1>Stop half-done API specifications</h1>
  
[![Maintained by blst security](https://img.shields.io/badge/maintained%20by-blst%20security-4F46E5)](https://www.blstsecurity.com/) 
[![docs](https://img.shields.io/badge/docs-passing-brightgreen)](https://www.blstsecurity.com/cherrybomb/Documentation)
[![Discord Shield](https://discordapp.com/api/guilds/914846937327497307/widget.png?style=shield)](https://discord.gg/WdHhv4DqwU)
</div>

# 💣 What is Cherrybomb?
Cherrybomb is a CLI tool that helps you avoid undefined user behavior by validating your API specifications.


# 🔨 How does it work?
Cherrybomb reads your API spec file (Open API Specification) and validates it for best practices and the [OAS specification](https://swagger.io/specification/),
then it tests to verify that the API follows the OAS file and tests for common vulnerabilities.</br>
The output is a detailed table with any issues found, guiding you to the exact problem and location to help you solve it quickly.

# 🐾 Get Started
## Installation
#### Using cURL
##### Linux/MacOS:
```
curl https://cherrybomb.blstsecurity.com/install	| /bin/bash
```
The script requires sudo permissions to move the cherrybomb bin into <b>/usr/local/bin/</b>.</br>
(If you want to view the shell script(or even help to improving it - [/scripts/install.sh](/scripts/install.sh))
#### Docker container
You can use our docker container that we host on our public repo in aws, though we require an API key for it, you can get it at [our CI pipeline integration maker](https://www.blstsecurity.com/CICD)(after you sign up)
```
docker run --mount type=bind,source=PATH_TO_OAS_DIR,destination=/home public.ecr.aws/t1d5k0l0/cherrybomb:latest cherrybomb oas -f home/OAS_NAME --api-key=API-KEY
```
#### Clone
You can also install Cherrybomb by cloning this repo, and building it using cargo:
```
git clone https://github.com/blst-security/cherrybomb && cd cherrybomb
cargo build --release
sudo mv ./target/release/cherrybomb /usr/local/bin
```

## Usage
After installing the CLI, verify it's working by running
```
cherrybomb --version
```

### OpenAPI specification scan
```
cherrybomb oas --file <PATH> --format <cli/txt/json> 
```
#### Output example:
![passive output](/images/passive.png)
![active output](/images/active.png)

### Generate Parameter Table
```
cherrybomb param-table --file <PATH> --name <SINGLE PARAM NAME(OPTIONAL)>
```

#### Table output example:
![param_table](/images/param_table.png)

### Generate Endpoint Table
```
cherrybomb ep-table --file <PATH> --name <SINGLE PARAM NAME(OPTIONAL)>
```
#### Table output example:
![ep_table](/images/ep_table.png)

# 🚧 Roadmap

 - [x] OAS 3 support
 - [x] Passive checks
 - [x] Parameter table 
 - [x] Improve installation script
 - [x] Endpoints table
 - [x] YAML support (currently only JSON is supported)
 - [x] Custom scans - optional checks + optional output
 - [x] Active scans
 - [ ] Ignore alerts + don't fail on info
 - [ ] More passive checks
 - [ ] Swagger 2 support (currently only version 3 is supported)
 - [ ] Homebrew/apt/crates.io support
 - [ ] GraphQL schema support

# 🍻 Integration

For all methods of integrating with BLST, please go to the [integrations folder](https://github.com/blst-security/cherrybomb/tree/main/integrations).

# 💪 Support

### Get help
If you have any questions, please send us a message to [support@blstsecurity.com](mailto:support@blstsecurity.com) or ask us on our [discord server](https://discord.gg/WdHhv4DqwU).
<br />
You are also welcome to open an Issue here on GitHub.

# 🤝 Contributing
You can find contribution options from our open issues, you should look for the "More passive checks" issue(it's a great issue to start from).
You can also find info about contributing new checks to Cherrybomb [here](https://github.com/blst-security/cherrybomb/blob/main/CONTRIBUTING.md).</br>
If you have any question or need any help talk to us over at our [discord server](https://discord.gg/WdHhv4DqwU) to see where and how can you contribute to our project.
