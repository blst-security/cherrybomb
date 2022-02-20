<div align="center">
  
![cherry_bomb_v4_3_1 (1)](https://user-images.githubusercontent.com/12970637/151692589-fe2cd8ef-9463-44b8-992e-9da0adff815e.png)

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
#### Direct download
You can also download the binary file directly from [our website](https://www.blstsecurity.com/cherrybomb).
<br />
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

#### More features
First, we have a mapping module that relies on HTTP logs and builds a map of the API.
<br />
Start mapping your logs by running
```
cherrybomb map --file <LOGS_FILE_PATH> --output <OUTPUT_FILE_NAME>
```

If you don't have an HTTP log file, but you have Burp suite logs, you are in luck, go to the scripts folder, there is a convertor script over there.
<br />
If there are any other formats you need conversion scripts to, message us on the [discord server](https://discord.gg/WdHhv4DqwU).
<br />
For futher insights, you can view your map visually in our web based visualizer: [https://www.blstsecurity.com/cherrybomb/Visualizer](https://www.blstsecurity.com/cherrybomb/Visualizer).

Then, you can run passive or active scans of your logs/APIs for anomalies:

**Passive** (1 step):
<br />
Run the decider only to **passively** check for anomalies in your logs, run
```
cherrybomb decide --file <LOGS_FILE_PATH> --map <MAPPED_FILE_PATH>
```

**Active** (2 steps):
After mapping, prepare the attacker by running the command below.
<br />
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
 - [ ] Improve installation script
 - [ ] Homebrew/APT support
 - [ ] Custom scans - optional checks + optional output + ignores(from alerts)
 - [ ] GraphQL schema support
 - [ ] Swagger 2 support (currently only version 3 is supported)
 - [ ] Active scans
 - [ ] More passive scans
 - [ ] Swagger and logs validator (compares your logs with the swagger to verify correctness)

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
