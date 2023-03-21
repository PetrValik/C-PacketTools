cmake_minimum_required(VERSION 3.0)

# Project configuration
project(hw03)

# Executable sources
set(SOURCES_DEMO demo.c pcap.c capture.c)
set(SOURCES_NFT nft.c pcap.c capture.c)

# Test sources
file(GLOB TESTS_GLOB "tests/test*.c")
foreach (file_path ${TESTS_GLOB})
    message("Found test: " ${file_path})
endforeach ()
set(TEST_SOURCES pcap.c capture.c
        tests/cut_main_runner.c
        ${TESTS_GLOB})

# Targets
set(EXECUTABLE_NFT nft)
set(EXECUTABLE_DEMO demo)
set(EXECUTABLE_TESTS nft-tests)

# Executable
add_executable(nft ${SOURCES_NFT})
add_executable(demo ${SOURCES_DEMO})

# Tests
add_definitions(-DCUT)
add_executable(nft-tests ${TEST_SOURCES})

# Configure compiler warnings
if (CMAKE_C_COMPILER_ID MATCHES Clang OR ${CMAKE_C_COMPILER_ID} STREQUAL GNU)
  # using regular Clang, AppleClang or GCC
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -pedantic -g -ggdb3")
elseif (${CMAKE_C_COMPILER_ID} STREQUAL MSVC)
  # using Visual Studio C++
  target_compile_definitions(${EXECUTABLE_NFT} PRIVATE _CRT_SECURE_NO_DEPRECATE)
  target_compile_definitions(${EXECUTABLE_DEMO} PRIVATE _CRT_SECURE_NO_DEPRECATE)
  target_compile_definitions(${EXECUTABLE_TESTS} PRIVATE _CRT_SECURE_NO_DEPRECATE)
  set(CMAKE_CXX_FLAGS "/permissive- /W4 /EHsc")
endif()

if(MINGW)
    target_compile_definitions(${EXECUTABLE_NFT} PRIVATE __USE_MINGW_ANSI_STDIO=1)
    target_compile_definitions(${EXECUTABLE_DEMO} PRIVATE __USE_MINGW_ANSI_STDIO=1)
    target_compile_definitions(${EXECUTABLE_TESTS} PRIVATE __USE_MINGW_ANSI_STDIO=1)
endif()

