cmake_minimum_required(VERSION 3.8.2)
project("CTR_DRBG")

# include_directories(./$ENV{MBEDTLS_BASE}/include)

# aux_source_directory(./$ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

set(libs
    mbedtls
 	mbedcrypto 
	mbedx509
)

set(targets
    CTR_DRBG
)

add_executable(CTR_DRBG CTR_DRBG.c)
target_link_libraries(CTR_DRBG ${libs})

# set(SOURCES
#     ${CMAKE_CURRENT_LIST_DIR}/list.c
#     ${MBEDTLS_SOURCES})
# add_executable(list ${SOURCES})