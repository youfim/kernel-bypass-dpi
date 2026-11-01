cmake_minimum_required(VERSION 3.20)
project(kernel_bypass_dpi VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_BENCHMARKS "Build benchmarks" ON)
option(BUILD_PYTHON_BINDINGS "Build Python nanobind bindings" ON)

# Optimization and warning flags
if(MSVC)
    add_compile_options(/W4 /permissive- /O2 /Oi /Ot)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3 -march=native)
endif()

# Core DPI Engine Library
add_library(dpi_core STATIC
    src/parser.cpp
    src/flow_table.cpp
    src/dpi_tls.cpp
    src/dpi_dns.cpp
    src/dpi_http.cpp
    src/capture_windivert.cpp
    src/capture_afxdp.cpp
    src/capture_pcap.cpp
)

target_include_directories(dpi_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Platform libraries
if(WIN32)
    target_link_libraries(dpi_core PUBLIC ws2_32)
endif()

# Unit Tests
if(BUILD_TESTS)
    enable_testing()

    add_executable(test_parsers tests/test_parsers.cpp)
    target_link_libraries(test_parsers PRIVATE dpi_core)
    add_test(NAME test_parsers COMMAND test_parsers)

    add_executable(test_ring_buffer tests/test_ring_buffer.cpp)
    target_link_libraries(test_ring_buffer PRIVATE dpi_core)
    add_test(NAME test_ring_buffer COMMAND test_ring_buffer)

    add_executable(test_flow_table tests/test_flow_table.cpp)
    target_link_libraries(test_flow_table PRIVATE dpi_core)
    add_test(NAME test_flow_table COMMAND test_flow_table)

    add_executable(test_dpi_l7 tests/test_dpi_l7.cpp)
    target_link_libraries(test_dpi_l7 PRIVATE dpi_core)
    add_test(NAME test_dpi_l7 COMMAND test_dpi_l7)
endif()

# Benchmarks
if(BUILD_BENCHMARKS)
    add_executable(bench_pcap_replay benchmarks/pcap_replay.cpp)
    target_link_libraries(bench_pcap_replay PRIVATE dpi_core)
endif()

# Python nanobind bindings
if(BUILD_PYTHON_BINDINGS)
    find_package(Python 3.10 COMPONENTS Interpreter Development REQUIRED)

    execute_process(
        COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE nanobind_ROOT
        RESULT_VARIABLE nanobind_RESULT
    )

    if(nanobind_RESULT EQUAL 0 AND EXISTS "${nanobind_ROOT}")
        list(APPEND CMAKE_PREFIX_PATH "${nanobind_ROOT}")
        find_package(nanobind CONFIG REQUIRED)

        nanobind_add_module(_dpi_engine
            python/bindings.cpp
        )
        target_link_libraries(_dpi_engine PRIVATE dpi_core)
        set_target_properties(_dpi_engine PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/python/dpi_engine"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/python/dpi_engine"
        )
    else()
        message(WARNING "nanobind not found. Python module _dpi_engine will not be built.")
    endif()
endif()
