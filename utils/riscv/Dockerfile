FROM ubuntu:22.04

MAINTAINER hydai hydai@secondstate.io
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt upgrade -y \
	&& apt install -y \
	autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev \
	gawk build-essential bison flex texinfo gperf libtool patchutils bc \
	zlib1g-dev libexpat-dev git \
	libglib2.0-dev libfdt-dev libpixman-1-dev \
	libncurses5-dev libncursesw5-dev

RUN git clone https://gitee.com/mirrors/riscv-gnu-toolchain \
		&& cd riscv-gnu-toolchain \
		&& git rm qemu \
		&& git submodule update --init --recursive \
		&& ./configure --prefix=/opt/riscv64 \
		&& make linux -j $(nproc)

ENV PATH="$PATH:/opt/riscv64/bin"

RUN apt install -y wget cmake ninja-build

RUN wget https://mirrors.tuna.tsinghua.edu.cn/gnu/binutils/binutils-2.32.tar.gz \
		&& tar -zxvf binutils-2.32.tar.gz \
		&& wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/llvm-project-13.0.0.src.tar.xz \
		&& tar -xf llvm-project-13.0.0.src.tar.xz \
		&& mv llvm-project-13.0.0.src llvm-project-13.0.0 \
		&& cd llvm-project-13.0.0 && mkdir build && cd build \
		&& cmake -G "Unix Makefiles" \
		-DCMAKE_BUILD_TYPE=Release \
		-DLLVM_TARGETS_TO_BUILD="RISCV" \
		-DLLVM_ENABLE_PROJECTS="clang" \
		-DLLVM_DEFAULT_TARGET_TRIPLE="riscv64-unknown-linux-gnu" \
		../llvm \
		&& cd .. \
		&& mkdir build-riscv && cd build-riscv \
		&& cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/opt/riscv64/sysroot \
		-DCMAKE_BUILD_TYPE=Release \
		-DLLVM_DEFAULT_TARGET_TRIPLE="riscv64-unknown-linux-gnu" \
		-DLLVM_TABLEGEN=/llvm-project-13.0.0/build/bin/llvm-tblgen \
		-DCLANG_TABLEGEN=/llvm-project-13.0.0/build/bin/clang-tblgen \
		-DLLVM_ENABLE_PROJECTS="lld" \
		-DLLVM_TARGET_ARCH="riscv64" \
		-DLLVM_TARGETS_TO_BUILD="RISCV" \
		-DCMAKE_FIND_ROOT_PATH=/opt/riscv64/riscv64-unknown-linux-gnu \
		-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
		-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
		-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
		-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
		-DCMAKE_SYSROOT="/opt/riscv64/sysroot" \
		-DCMAKE_C_COMPILER=riscv64-unknown-linux-gnu-gcc \
		-DCMAKE_CXX_COMPILER=riscv64-unknown-linux-gnu-g++ \
		-DLLVM_BINUTILS_INCDIR=/binutils-2.32/include \
		../llvm \
		&& ninja \
		&& ninja install

RUN rm -rf /var/lib/apt/lists/*
