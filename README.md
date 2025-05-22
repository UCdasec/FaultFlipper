# Welcome to FaultFlipper 👋
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg?cacheSeconds=2592000)

> Hardware Fault Simulator at the Software Level

## NOTICE: 
I am splitting this tool into two seperate clis.... bare with me. 

## Installation

We use pixi (conda replacement) for dependency management where possible. 
Additionally, the apt repository is used for compilers (i.e RISCV64 compiler)

Install pixi with:
```sh
curl -fsSL https://pixi.sh/install.sh | bash
```
Or if your `.. | bash` adverse visit their site at: https://pixi.sh/latest/

Then enter the environment with:
```sh
pixi shell
```

Each ***target*** will need its _own compiler, toolchain and emulator_. This may very depending on your 
system. For example, below is a list of command that worked on ubuntu 22.04 and wsl to install
a handful of compilers and emulators.

```bash
sudo apt install gcc-riscv64-linux-gnu
sudo apt-get install libc6-riscv64-cross
sudo apt-get install gcc-arm-linux-gnueabi
sudo apt install qemu-arm-static
sudo apt install qemu-aarch64-static
sudo apt install aarch64-linux-gnu-gcc

# For generating PDF reports:
sudo apt install pandoc
sudo apt install texlive-xetex
```

## Usage
The CLI script is the file `src/cli.py`. This file has a handful of commands
that can be run to analyze a binary. To see a list of commands run:
```sh
python src/cli.py --help
```

## Example Experiments

An example experiment that will (1) compile the binary `test_files/password_check.c`
(2) Generate ***mutated*** binaries with the NOP mutation (3) Run the files 
and record the run results:
```sh 
python src/cli.py para-nop test_files/password_check.c --program-input wrong --expected-returncode 0 --expected-stdout Correct --list-expected --timeout 4 --out-dir para_nop_x86 --target x86_64 --num-cpus 8
```

To make running the CLI easier you can use the `run` command and provide an 
***experiment profile*** that defines the experiment. An example profile is:
```toml
[experiment.para_nop_x86_64]
command = "para_nop"
program-file = "test_files/password_check.c"
program-input = "wrong\n"
expected-returncode = 0 
expected-stdout = "Correct"
list-expected = false 
timeout = 4 
out-dir = "experiments/para_nop_x86_64_password_check"
yes= true
target = "x86_64"
num_cpus=8
```
To run the profile use the command 
```sh
python src/cli.py run profiles/x86_64_nop_password_check.toml
```

## Author

👤 **UcDasec Lab**
* Github: [@ESPR3SS0](https://github.com/UCdasec)

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

- [x] Parallelize NOP mutation 
- [x] Parallelize BIT mutatation
    - [ ] BUG: Para-nop returns slightly different results from Seq-nop


Currently the tool now has great support for single experiments! It may be 
beneficial in the future to easily attempt many fault patterns on the same 
binary (or even a batch of binaries) quickly so in the future... 
- [ ] With a similar interface to "nop_exp" support running _many_ fault models
- [ ] With a similar interface to "nop_exp" support running _many_ binaries

-Or- 
I can keep _everything_ module. One binary, one test, one set of results. Then 
I can provide a nice interface to compare the results... I think this is a better 
approach 
- [ ] Add a "overhead analyzer" 
- [ ] Add results comparison analyzer

Unfortunately for research purposes it makes sense to force the user to provide
the source code. However, for pratical purposes it makes more sense to only 
provide the binary... therefore I can (1) Make source code optional (2) Provide 
seperate command that doesn't ask for source code. For "deterministic" reasons
I will do (2)

- [ ] Make a "nop_exp" that does not require source code

- [ ] Investigate differences between parallel implementaitons and the sequential implementations

- [ ] Add support for more complex compile commands 
    - [ ] Provide a shell script for compilation 
    - [ ] Provide a make file 

- [ ] When using more complex compile commands still track flags


***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_
