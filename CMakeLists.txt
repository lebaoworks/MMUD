cmake_minimum_required(VERSION 3.10)
project(PROGRAM_MMUD)

set(MbedTLS_DIR ${PROJECT_SOURCE_DIR}/mbedtls_built/cmake)
find_package(MbedTLS)

set(executables
    CHAP
)

foreach(exe IN LISTS executables)
    add_executable(${exe} ${exe}.c)
    target_link_libraries(${exe}
        PUBLIC MbedTLS::mbedtls
               MbedTLS::mbedcrypto
               MbedTLS::mbedx509)
endforeach()