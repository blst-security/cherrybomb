<div align="center">
  
![cherry_bomb_v5_1](https://user-images.githubusercontent.com/12970637/159654379-eaff2dde-ba9c-403b-9f23-d412b4657847.png)

  <h1>Stop half-done API specifications</h1>
  
[![Maintained by blstsecurity](https://img.shields.io/badge/maintained%20by-blst%20security-4F46E5)](https://www.blstsecurity.com/) [![docs](https://img.shields.io/badge/docs-passing-brightgreen)](https://www.blstsecurity.com/cherrybomb/Documentation)
[![Discord Shield](https://discordapp.com/api/guilds/914846937327497307/widget.png?style=shield)](https://discord.gg/WdHhv4DqwU)
</div>

# 💣 What is Cherrybomb?
Cherrybomb is a CLI tool that helps you avoid undefined user behavior by validating your API specifications.

Our CLI tool is open source, enabling support from both the OpenAPI and Rust communities.

# 🔨 How does it work?
It takes in an OAS file, runs a series of checks on it to make sure everything is on par with the OAS, and outputs a detailed table with any alerts found, guiding you to the exact problem and location to help you solve it quickly.

It can also take in your logs and check them for business logic flaws.

# 🐾 Get Started
## Installation
#### Using cURL
##### Linux/MacOS:
```
curl https://cherrybomb.blstsecurity.com/install	| /bin/bash
```
The script requires sudo permissions to move the cherrybomb bin into <b>/usr/local/bin/</b>.</br>
(If you want to view the shell script(or even help to improving it - [/scripts/install.sh](/scripts/install.sh))
#### Direct download
You can also download the binary file directly from [our website](https://www.blstsecurity.com/cherrybomb).
<br />
This is a binary file and you DO NOT have to install Rust.
If you use this method you should run this command:
```
mkdir ~/.cherrybomb
```
To create a .cherrybomb dir in the home directory.

## Usage
After installing the CLI, verify it's working by running
```
cherrybomb --version
```

### OpenAPI specification scan
```
cherrybomb swagger --file <PATH> --output <PATH> --verbosity <0/1/2>
```
Or
```
cherrybomb oas --file <PATH> --output <PATH> --verbosity <0/1/2>
```
#### Output example for verbosity level 1:
![checks_table](/images/checks_table.png)
#### Output example for verbosity level 0:
![alerts_table](/images/checks_table.png)

### Genrate Parameter Table
```
cherrybomb swagger --file <PATH> --param-table
```
Or
```
cherrybomb oas --file <PATH> --param-table
```
#### Table output example:
![param_table](/images/param_table.png)

### More features
First, we have a mapping module that relies on HTTP logs and builds a map of the API.
<br />
Start mapping your logs by running
```
cherrybomb map --file <LOGS_FILE_PATH> --output <OUTPUT_FILE_NAME> --hint <OAS FILE NAME>
```

If you don't have an HTTP log file, but you have Burp suite logs, you are in luck, go to the scripts folder, there is a convertor script over there.
<br />
If there are any other formats you need conversion scripts to, message us on the [discord server](https://discord.gg/WdHhv4DqwU).
<br />
For futher insights, you can view your map visually in our web based visualizer: [https://www.blstsecurity.com/cherrybomb/Visualizer](https://www.blstsecurity.com/cherrybomb/Visualizer).

In the future, if you want to load new logs to an existing map file, run
```
cherrybomb load --file <LOGS_FILE_PATH> --map <MAPPED_FILE_PATH>
```

# 🪦 (!)Deprecation notice:
The <b>Attacker</b> and <b>Decider</b> modules will be deprecated(!) in our the next release(version 0.6).
We are doing it since we have barely seen any usage of the modules thus far.
Please let us know if you are indeed using those features and don't want them to be deprecated.

# 🚧 Roadmap

 - [x] OAS 3 support
 - [x] Passive checks
 - [x] Parameter table 
 - [x] Improve installation script
 - [ ] Homebrew/APT support
 - [ ] Custom scans - optional checks + optional output + ignores(from alerts)
 - [ ] GraphQL schema support
 - [ ] Swagger 2 support (currently only version 3 is supported)
 - [ ] Active scans
 - [ ] More passive scans
 - [ ] Swagger and logs validator (compares your logs with the swagger to verify correctness)

# 🍻 Integration

For all methods of integrating with BLST, please go to the [integrations folder](https://github.com/blst-security/cherrybomb/tree/main/integrations).

# 💪 Support
### Documentation
Please read [our documentation](https://www.blstsecurity.com/cherrybomb/Documentation) to understand the format of sessions our mapper needs to function correctly.

### Get help
If you have any questions, please send us a message to [support@blstsecurity.com](mailto:support@blstsecurity.com).
<br />
You are also welcome to open an Issue here on GitHub.

# 🤝 Contributing
Please talk to us over at our [discord server](https://discord.gg/WdHhv4DqwU) to see where and how can you contribute to our project.
<br />
You can also find info about how to contribute to Cherrybomb [here](https://github.com/blst-security/cherrybomb/blob/main/CONTRIBUTING.md).
