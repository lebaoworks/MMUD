set(executables
    dh_client
    dh_server
)

foreach(exe IN LISTS executables)
    add_executable(${exe} ${exe}.c)
    target_include_directories(${exe} PRIVATE ${PROJECT_SOURCE_DIR})
    target_link_libraries(${exe}
        PUBLIC MbedTLS::mbedtls
               MbedTLS::mbedcrypto
               MbedTLS::mbedx509)
endforeach()
