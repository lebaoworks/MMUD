README
===================

This repository is for educational purposes only.

Tested on WSL1 Ubuntu 20.04.3 LTS

## Requirements
---------

-   GNU Make
-   CMake
-   Mbed TLS

### Mbed TLS 3.0.0

Source:    

    https://github.com/ARMmbed/mbedtls/releases

## Compilation

First, build MbedTLS, just enter at the command line:

    mkdir ./mbedtls_built && cd ./mbedtls_built
    cmake /path/to/mbedtls_source
    cmake --build .

Second, build project:

    mkdir ./_built && cd ./_built
    cmake ../
    cmake --build .

## Run

More infomations in README.md of each program