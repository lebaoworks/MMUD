set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(executables
    krb_server
    krb_client
)

foreach(exe IN LISTS executables)
    add_executable(${exe} ${exe}.c)
    target_include_directories(${exe} PRIVATE ${PROJECT_SOURCE_DIR})
    target_compile_options(${exe} PRIVATE "-pthread")
    target_link_libraries(${exe}
        PUBLIC MbedTLS::mbedtls
               MbedTLS::mbedcrypto
               MbedTLS::mbedx509)
    target_link_libraries(${exe} PRIVATE Threads::Threads)
endforeach()