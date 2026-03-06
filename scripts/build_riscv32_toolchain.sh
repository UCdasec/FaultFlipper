sudo apt-get update
sudo apt-get install -y autoconf automake autotools-dev curl python3 \
  libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo \
  gperf libtool patchutils bc zlib1g-dev libexpat-dev ninja-build git cmake

git clone --recursive https://github.com/riscv-collab/riscv-gnu-toolchain
cd riscv-gnu-toolchain

# RV32GC with ILP32D ABI (adjust if you don’t want F/D)
./configure --prefix=/opt/riscv32-linux-gnu --with-arch=rv32gc --with-abi=ilp32d
make linux   # builds the Linux/glibc cross toolchain

export PATH=/opt/riscv32-linux-gnu/bin:$PATH

sudo ln -s /opt/riscv32-linux-gnu/sysroot /usr/riscv32-linux-gnu
