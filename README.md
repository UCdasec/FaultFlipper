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
# Compiler installs: 
sudo apt install gcc-riscv64-linux-gnu
sudo apt-get install libc6-riscv64-cross
sudo apt-get install gcc-arm-linux-gnueabi
sudo apt install aarch64-linux-gnu-gcc

# If you want to use riscv32... warning this will take awhile
sudo ./scripts/build_riscv32_toolchain.sh

# QEMU install ...
sudo apt install qemu-user-static

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

## Example Experiments - Password Check

An example experiment that will (1) compile the binary `test_files/password_check.c`
(2) Generate ***mutated*** binaries with the NOP mutation (3) Run the files 
and record the run results:
```sh 
pixi run cli x-nop test_files/password_check.c --program-input wrong --expected-returncode 0 --expected-stdout Correct --list-expected --timeout 2 --out-dir results/1nop_x86 --target x86_64 --num-cpus 24 --optimization O0 --num-nops 1
```

To make running the CLI easier you can use the `run` command and provide an 
***experiment profile*** that defines the experiment. An example profile is:
```toml
[experiment.nop_x86_64]
command = "x_nop"
program-file = "test_files/password_check.c"
program-input = "wrong\n"
expected-returncode = 0 
expected-stdout = "Correct"
list-expected = false 
timeout = 4 
out-dir = "experiments/1_nop_x86_64_password_check"
yes= true
target = "x86_64"
num_cpus=24
num_nops=1
```
To run the profile use the command 
```sh
python src/cli.py run profiles/x86_64_nop_password_check.toml
```

To obtain a trace that maps all asm address to source lines, here is an example:
```bash
python tracer_source/simple_mapper.py --binary experiments/1nop_arm32_opt0_password_check/password_check.o --source test_files/password_check.c --arch arm32
```

## Example Experiments - MLP 

This section shows how to generate a neural-network experiment config and run
it on the face dataset images bundled in `test_packages/emlearn_example/`.

1. Generate the NN experiment config (this writes a TOML profile):
```sh
pixi run cli nn-generate-exp-files \
  --exp-file profiles/face_mlp.toml \
  --binary test_packages/emlearn_example/STATI_face_mlp_x86.o \
  --timeout 4 \
  --out-dir experiments/face_mlp_nop \
  --input-dir test_packages/emlearn_example/image_dir/test/faces \
  --expected-correct <CORRECT_COUNT>
```

`<CORRECT_COUNT>` should be the number of correct predictions produced by the
unmutated binary on the dataset (you can compute this with
`test_packages/emlearn_example/c_model_tester.py`).

2. Run the NN experiment using the generated config:
```sh
pixi run cli run profiles/face_mlp.toml
```


## Author

👤 **UcDasec Lab**
* Github: [@ESPR3SS0](https://github.com/UCdasec)

👤 **ESPR3SS0**
* Github: [@ESPR3SS0](https://github.com/ESPR3SS0)

## Show your support

Give a ⭐️ if you think this project is interesting!

## Roadmap  - First priority 

- [ ] Updated readme examples to minimally cover the experiments in the paper
    - [ ] Generate classifier profile


## Roadmap - Second priority

- [ ] Adding clean install script (focus on handling non-pypi dependencies)
- [ ] Modularizing the Experiment Runner from the Classifier of the results
- [ ] Splitting code into seperate modules (angr, qemu, tracing, etc)
- [ ] Move `angr-nop-nocomp-inout` to be incorporated as a backend to another command instead of being a standalone command


***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_
