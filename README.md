# Welcome to FaultSim 👋
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg?cacheSeconds=2592000)

> Hardware Fault Simulator at the Software Level

## Installation

We use pixi (conda replacement) for dependency management where possible. 
Additionally, the apt repository is used for compilers (i.e RISCV64 compiler)

Install pixi with:
```sh
curl -fsSL https://pixi.sh/install.sh | bash
```
Or if your ` ... | bash` adverse visit their site at: https://pixi.sh/latest/

Then enter the environment with:
```sh
pixi shell
```

Each target will need its _own compiler_. This may very depending on your 
system. For example, below is the command used to install the riscv64 compiler.

```bash
sudo apt install gcc-riscv64-linux-gnu
sudo apt-get install libc6-riscv64-cross
```

## Usage

```sh
python src/main.py --help
```

## Author

👤 **ESPR3SS0**

* Github: [@ESPR3SS0](https://github.com/ESPR3SS0)

## Show your support

Give a ⭐️ if you think this project is interesting!

## Roadmap 

- [x] Add RISC 
- [x] Add ARM32
- [x] Add ARM64
- [x] Profile all exit codes returned by programs 
- [x] Analyze faults selected by the user 
    - [x] Print the address of the fault
    - [x] Print the surrounding x lines of instructions 
    - [x] Print the old and new instruction 
- [x] Allow chains of experiments to be run
    - [x] I.E instead of using shell scripts make a config file 
- [x] When comparing binaries align instructions based on address
- [x] Add a toml that sets up an experiment and saves it
- [x] Provide compilation settings in a .toml file
    - [x] Handle libraries in .toml
    - [x] Handle compiler in .toml

- [ ] Program to parse the results.csv and auto display a comparison of the 
        vanilla assmebly and the mutated assembly showing X line above and 
        below the mutated address

- [ ] Parallelize NOP mutation 
- [ ] Parallelize BIT mutatation

Currently the tool now has great support for single experiments! It may be 
beneficial in the future to easily attempt many fault patterns on the same 
binary (or even a batch of binaries) quickly so in the future... 
- [ ] With a similar interface to "nop_exp" support running _many_ fault models
- [ ] With a similar interface to "nop_exp" support running _many_ binaries

Unfortunately for research purposes it makes sense to force the user to provide
the source code. However, for pratical purposes it makes more sense to only 
provide the binary... therefore I can (1) Make source code optional (2) Provide 
seperate command that doesn't ask for source code. For "deterministic" reasons
I will do (2)

- [ ] Make a "nop_exp" that does not require source code


***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_
Compile arm32: arm-linux-gnueabi-gcc -o test.o test_files/password_check.c
