cmake_minimum_required(VERSION 3.8.2)
project("big_prime_number")

# include_directories(./$ENV{MBEDTLS_BASE}/include)

# aux_source_directory(./$ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

set(libs
    mbedtls
 	mbedcrypto 
	mbedx509
)

set(targets
    big_prime_number
)

add_executable(big_prime_number big_prime_number.c)
target_link_libraries(big_prime_number ${libs})

# set(SOURCES
#     ${CMAKE_CURRENT_LIST_DIR}/list.c
#     ${MBEDTLS_SOURCES})
# add_executable(list ${SOURCES})