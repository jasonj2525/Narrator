# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

# If the CC environment variable has been specified or if the CMAKE_C_COMPILER
# cmake variable has been passed to cmake, use the C compiler that has been
# specified. Otherwise, prefer clang. Same for C++ compiler.
# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-10 clang)
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-10 clang++)
  endif ()
endif ()

project("Attestation Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(BOOST_ROOT /usr/include/boost) 

find_package(Boost COMPONENTS filesystem regex REQUIRED) 
set(OE_CRYPTO_LIB
    openssl
    CACHE STRING "Crypto library used by enclaves.")

add_subdirectory(common)
add_subdirectory(enclave)
add_subdirectory(host)

add_custom_target(sign ALL DEPENDS enclave_a_signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS attestation_host sign
    COMMAND
    attestation_host  ${CMAKE_BINARY_DIR}/enclave/enclave_a.signed)
    #sudo ./host/attestation_host ./enclave/enclave_a.signed 8004 192.168.1.107 8001 192.168.1.107
endif ()
