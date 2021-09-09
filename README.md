README
===================

This repository is only for educational purposes.

Has tested on WSL1 Ubuntu 20.04.3 LTS

## Requirements
---------

-   GNU Make
-   CMake
-   Mbed TLS

### Mbed TLS 3.0.0

Source:    

    https://github.com/ARMmbed/mbedtls/releases

## Compilation

Build MbedTLS, just enter at the command line:

    mkdir ./mbedtls_built && cd ./mbedtls_built
    cmake /path/to/mbedtls_source
    cmake --build .

Build project:

    mkdir ./_built && cd ./_built
    cmake ../
    cmake --build .

## Run

Run with argument "auth" to setup authenticatior

    ./CHAP auth

Run with argument "peer" to try authenticate

    ./CHAP peer