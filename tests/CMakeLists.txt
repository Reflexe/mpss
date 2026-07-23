# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

# Integrated mode: select the common tests, then let each platform own its runner
# and packaging.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/test_entry.cpp")
    set(mpss_TESTS_LINK_LIBRARIES GTest::gtest)

    if(TARGET ${mpss_TARGET})
        list(APPEND mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/mpss_tests.cpp")
    endif()
    if(TARGET ${mpss_openssl_TARGET})
        list(APPEND mpss_TESTS_FILES
            "${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_tests.cpp"
            "${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_e2e_test.cpp"
        )
        # mpss comes transitively through mpss_openssl's PUBLIC dependency.
        list(APPEND mpss_TESTS_LINK_LIBRARIES ${mpss_openssl_TARGET})
    elseif(TARGET ${mpss_TARGET})
        list(APPEND mpss_TESTS_LINK_LIBRARIES ${mpss_TARGET})
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        add_executable(mpss_tests MACOSX_BUNDLE
            ${mpss_TESTS_FILES}
            "${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp"
        )
        target_link_libraries(mpss_tests PRIVATE ${mpss_TESTS_LINK_LIBRARIES})
        add_subdirectory(ios)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
        add_subdirectory(android)
    else()
        add_executable(mpss_tests
            ${mpss_TESTS_FILES}
            "${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp"
        )
        target_link_libraries(mpss_tests PRIVATE ${mpss_TESTS_LINK_LIBRARIES})
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        # The Windows tests call CNG (NCrypt*) directly to verify storage tier and export policy.
        target_link_libraries(mpss_tests PRIVATE ncrypt)
    endif()
    return()
endif()

# Standalone mode: build tests against an installed or build-tree mpss.
#
# Usage:
#   cmake -S tests -B build_tests \
#         -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT_DIR/scripts/buildsystems/vcpkg.cmake \
#         -Dmpss_ROOT=/path/to/mpss/install/dir \
#         -DCMAKE_BUILD_TYPE=<Debug|Release>
#   cmake --build build_tests --target mpss_tests
project(mpss_tests LANGUAGES CXX)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR
        "Standalone Android tests are not supported. Configure the top-level "
        "MPSS project with MPSS_BUILD_TESTS=ON.")
endif()

# Accept MPSS_ROOT as a case-insensitive alias for mpss_ROOT.
if(DEFINED MPSS_ROOT AND NOT DEFINED mpss_ROOT)
    set(mpss_ROOT "${MPSS_ROOT}")
endif()

find_package(mpss REQUIRED)
find_package(GTest CONFIG REQUIRED)

# Always compile the reusable entry point and desktop runner.
set(mpss_TESTS_SOURCES test_entry.cpp test_runner.cpp)

# Conditionally add tests depending on what the installed mpss provides.
if(MPSS_CORE_FOUND)
    list(APPEND mpss_TESTS_SOURCES mpss_tests.cpp)
endif()
if(MPSS_OPENSSL_FOUND)
    list(APPEND mpss_TESTS_SOURCES
        mpss_openssl_tests.cpp
        mpss_openssl_e2e_test.cpp
    )
endif()

add_executable(mpss_tests ${mpss_TESTS_SOURCES})
target_link_libraries(mpss_tests PRIVATE GTest::gtest)

# Link against the best available mpss target. mpss-openssl pulls in mpss
# transitively through its PUBLIC dependency, so we only need one link.
if(MPSS_OPENSSL_FOUND)
    if(TARGET mpss::mpss_openssl)
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_openssl)
    else()
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_openssl_static)
    endif()
elseif(MPSS_CORE_FOUND)
    if(TARGET mpss::mpss)
        target_link_libraries(mpss_tests PRIVATE mpss::mpss)
    else()
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_static)
    endif()
endif()

# Add the parent directory to the include path so that test-local headers
# (included via paths like "mpss/../tests/...") resolve correctly.
target_include_directories(mpss_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # The Windows tests call CNG (NCrypt*) directly to verify the key export policy.
    target_link_libraries(mpss_tests PRIVATE ncrypt)
endif()
