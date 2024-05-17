cmake_minimum_required(VERSION 3.5.1)
project(peafowl VERSION 1.1.4)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_C_STANDARD 11)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")

###########
# Options #
###########
option (ENABLE_TESTS "Enables testing" OFF)
option (ENABLE_CPPCHECK "Enables cppcheck checks" OFF)
option (ENABLE_CODECOV "Enables code coverage reports" OFF)
option (ENABLE_CLANGFORMAT "Enables clang-format formatting" OFF)
option (ENABLE_PYTHON "Enables generation of Python code" OFF)
option (ENABLE_C "Enables generation of C/C++ libraries" ON)
option (ENABLE_DEMO "Install demo executables" OFF)
option (ENABLE_OPENSSL "Enable the search of OpenSSL" ON)

add_compile_options(-Wall -Wextra -pedantic)

# Needed for some libc to have proper struct {tcp,udp}hdr definition
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE")

find_package(PCAP)
if (ENABLE_OPENSSL)
  find_package(OpenSSL)
endif (ENABLE_OPENSSL)

# This must be the first thing done, since COVERAGE_COMPILER_FLAGS must be used by all the targets
###########
# codecov #
###########
if (ENABLE_CODECOV)
    set (CMAKE_BUILD_TYPE Debug)
    if (NOT ENABLE_TESTS)
        message (FATAL_ERROR "You need to define -DENABLE_TESTS=ON when you use -DENABLE_CODECOV=ON")
    endif()
    include(CodeCoverage)
    APPEND_COVERAGE_COMPILER_FLAGS()
endif (ENABLE_CODECOV)

###########
# Library #
###########
add_subdirectory(src)
if (ENABLE_C AND ENABLE_DEMO)
    add_subdirectory(demo)
endif (ENABLE_C AND ENABLE_DEMO)

############
# cppcheck #
############
if (ENABLE_CPPCHECK)
    include(cmake/cppcheck.cmake)
endif (ENABLE_CPPCHECK)

###########
# Testing #
###########
if (ENABLE_TESTS)
    if (NOT PCAP_FOUND)
        message(FATAL_ERROR "libpcap needs to be installed to run tests")
    else()
        enable_testing()
        add_subdirectory(test)
    endif (NOT PCAP_FOUND)
endif (ENABLE_TESTS)

###########
# codecov #
###########
if (ENABLE_CODECOV)
    set(COVERAGE_GCOVR_EXCLUDES 'src/external/*' 'test/*' 'demo/*' 'experiments/*')
    SETUP_TARGET_FOR_COVERAGE_GCOVR_XML(
        NAME coverage
        EXECUTABLE make test
        DEPENDENCIES peafowl_static
    )
endif (ENABLE_CODECOV)

################
# clang-format #
################
if (ENABLE_CLANGFORMAT)
  include(cmake/clang_format.cmake)
endif (ENABLE_CLANGFORMAT)
