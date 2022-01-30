<div align="center">
  
![cherry_bomb_v4_3_1](https://user-images.githubusercontent.com/12970637/151691632-979eb3fc-0181-40a2-80e5-e455dcb78d9c.png)

[![Maintained by blstsecurity](https://img.shields.io/badge/maintained%20by-blst%20security-4F46E5)](https://www.blstsecurity.com/) [![docs](https://img.shields.io/badge/docs-passing-brightgreen)](https://www.blstsecurity.com/cherrybomb/Documentation)
![Discord Shield](https://discordapp.com/api/guilds/914846937327497307/widget.png?style=shield)
</div>

# 🧨 What is Cherrybomb?
Cherrybomb is a CLI tool that helps you avoid undefined user behavior by validating your API specifications.

Our CLI too is open source, enabling support from both the OpenAPI and Rust communities.

# 🔨 How does it work?
It takes in a swagger file, runs a series of checks on it to make sure everything is on par with the OAS, and outputs a detailed table with any alerts found, guiding you to the exact problem and location to help you solve it quickly.

It can also take in your logs and check them for business logic flaws.

# 🐾 Get Started
## Installation
#### Using Wget 
##### Linux:
```
wget download-cherrybomb.blstsecurity.com/cherrybomb_linux && chmod +x cherrybomb_linux && mv cherrybomb_linux cherrybomb
```
##### MacOS:
```
wget download-cherrybomb.blstsecurity.com/cherrybomb_mac && chmod +x cherrybomb_mac && mv cherrybomb_mac cherrybomb
```

#### Direct download
You can also download the binary file directly from [our website](https://www.blstsecurity.com/cherrybomb).
This is a binary file and you DO NOT have to install Rust.

## Usage
After installing the CLI, verify it's working by running
```
cherrybomb --version
```

#### Swagger scan
```
cherrybomb swagger --file <PATH> --output <PATH> --verbosity <0/1/2>
```

#### Logs scan
First, start by mapping your logs by running
```
cherrybomb map --file <LOGS_FILE_PATH> --output <OUTPUT_FILE_NAME>
```
##### Passive checking for anomalies (1 step)
To run the decider only to **passively** check for anomalies in your logs, run
```
cherrybomb decide --file <LOGS_FILE_PATH> --map <MAPPED_FILE_PATH>
```
##### Active attacking and checking for anomalies (2 steps)
After mapping, prepare the attacker by running the command below.
This will print the populations (API groups) so you can choose which one you want to run the attacker on.
```
cherrybomb prepare --url <URL_TO_ATTACK> --map <MAPPED_FILE_PATH>
```
Now you can use the attacker to **actively** attack the API by running
```
cherrybomb attack --map <MAPPED_FILE_PATH> (the same one you used in the prepare step) --output <OUTPUT_FILE_NAME> --population <POPULATION_NUMBER> (the one you got from the prepare step) --generations <MAX_GENERATIONS_NUMBER> --verbosity <VERBOSITY_LEVEL>
```
In the future, if you want to load new logs to an existing map file, run
```
cherrybomb load --file <LOGS_FILE_PATH> --map <MAPPED_FILE_PATH>
```
# 🚧 Roadmap

 - [x] OAS 3 support
 - [x] Passive checks
 - [ ] Homebrew/APT support
 - [ ] Custom scans - optional checks + optional output + ignores(from alerts)
 - [ ] Swagger 2 support (currently only version 3 is supported)
 - [ ] Active scans
 - [ ] More passive scans
 - [ ] Swagger and logs validator (compares your logs with the swagger to verify correctness)

# 💪 Support
### Documentation
Please read [our documentation](https://www.blstsecurity.com/cherrybomb/Documentation) to understand the format of sessions our mapper needs to function correctly.

### Get help
If you have any questions, please send us a message to [support@blstsecurity.com](mailto:support@blstsecurity.com).
You are also welcome to open an Issue here on GitHub.

# 🤝 Contributing
You can find info about how to contribute to Cherrybomb [here](https://github.com/blst-security/cherrybomb/blob/main/CONTRIBUTING.md).
You can also talk to us in our developers' [discord channel](https://discord.gg/WdHhv4DqwU).
