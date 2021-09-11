cmake_minimum_required(VERSION 3.10)
project(PROGRAM_MMUD)

set(MbedTLS_DIR ${PROJECT_SOURCE_DIR}/mbedtls_built/cmake)
find_package(MbedTLS)

add_subdirectory(programs)