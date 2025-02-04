# Welcome to FaultSim 👋
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg?cacheSeconds=2592000)

> Hardware Fault Simulator at the Software Level

## Installation

We use pixi for dependency management where possible. It's essentially conda but newer and shiner.

For compilers, we install via apt repository.


Install pixi with:
```sh
curl -fsSL https://pixi.sh/install.sh | bash
```
Or if your ` ... | bash` adverse visit their site at: https://pixi.sh/latest/

Then enter the environment with:
```sh
pixi shell
```

To install the required compilers:
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
- [ ] Analyze faults selected by the user 
    - [ ] Print the address of the fault
    - [ ] Print the surrounding x lines of instructions 
    - [ ] Print the old and new instruction 
- [x] Allow chains of experiments to be run
    - [x] I.E instead of using shell scripts make a config file 
- [ ] When comparing binaries align instructions based on address
- [x] Add a toml that sets up an experiment and saves it


***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_
Compile arm32: arm-linux-gnueabi-gcc -o test.o test_files/password_check.c
