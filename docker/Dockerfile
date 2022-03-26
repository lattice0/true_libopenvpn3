FROM ubuntu:focal

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update \
&& apt-get install -y clang-6.0 lldb iptables iproute2 cmake \
build-essential libmbedtls-dev libssl-dev liblz4-dev curl git \
xz-utils wget libncurses5

RUN curl --proto '=https' --tlsv1.2 -o rust.sh https://sh.rustup.rs\
    && /bin/bash rust.sh -y

#RUN wget -O clang.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
#&& tar xf clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
#&& mv clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04 /usr/local/clang

#TODO: add verification of signature
RUN wget -O clang.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
&& mkdir clang && tar xf clang.tar.xz -C clang --strip-components 1 \
&& mv clang /usr/local/clang

WORKDIR /home/project

ENV PATH="/root/.cargo/bin:${PATH}"
ENV PATH="/usr/local/cmake/bin:${PATH}"
ENV PATH="/usr/local/clang/bin:${PATH}"