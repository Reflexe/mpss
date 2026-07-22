# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

if(NOT APPLE)
    message(FATAL_ERROR "The iOS simulator test helper must run on macOS.")
endif()

if(NOT DEFINED MPSS_SOURCE_DIR)
    get_filename_component(MPSS_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
endif()
if(NOT DEFINED MPSS_BUILD_DIR)
    set(MPSS_BUILD_DIR "${MPSS_SOURCE_DIR}/build-ios-simulator")
endif()
if(NOT DEFINED MPSS_CONFIGURATION)
    set(MPSS_CONFIGURATION Debug)
endif()
if(NOT DEFINED MPSS_IOS_DEPLOYMENT_TARGET)
    set(MPSS_IOS_DEPLOYMENT_TARGET 16.3)
endif()
if(NOT DEFINED MPSS_VCPKG_ROOT)
    if(DEFINED ENV{VCPKG_ROOT})
        set(MPSS_VCPKG_ROOT "$ENV{VCPKG_ROOT}")
    elseif(EXISTS "${MPSS_SOURCE_DIR}/../vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(MPSS_VCPKG_ROOT "${MPSS_SOURCE_DIR}/../vcpkg")
    else()
        message(FATAL_ERROR
            "Set MPSS_VCPKG_ROOT or VCPKG_ROOT to a vcpkg checkout.")
    endif()
endif()

set(mpss_TOOLCHAIN_FILE
    "${MPSS_VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
if(NOT EXISTS "${mpss_TOOLCHAIN_FILE}")
    message(FATAL_ERROR "vcpkg toolchain not found: ${mpss_TOOLCHAIN_FILE}")
endif()

file(MAKE_DIRECTORY "${MPSS_BUILD_DIR}")

set(mpss_CONFIGURE_COMMAND
    "${CMAKE_COMMAND}"
    -S "${MPSS_SOURCE_DIR}"
    -B "${MPSS_BUILD_DIR}"
    -G Xcode
    "-DCMAKE_SYSTEM_NAME=iOS"
    "-DCMAKE_OSX_SYSROOT=iphonesimulator"
    "-DCMAKE_OSX_ARCHITECTURES=arm64"
    "-DCMAKE_OSX_DEPLOYMENT_TARGET=${MPSS_IOS_DEPLOYMENT_TARGET}"
    "-DCMAKE_TOOLCHAIN_FILE=${mpss_TOOLCHAIN_FILE}"
    "-DVCPKG_TARGET_TRIPLET=arm64-ios-simulator"
    "-DMPSS_BUILD_MPSS_CORE_STATIC=ON"
    "-DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON"
    "-DMPSS_BUILD_TESTS=ON"
)
if(DEFINED MPSS_VCPKG_BINARY_SOURCES)
    list(APPEND mpss_CONFIGURE_COMMAND
        "-DVCPKG_BINARY_SOURCES=${MPSS_VCPKG_BINARY_SOURCES}")
endif()

execute_process(
    COMMAND ${mpss_CONFIGURE_COMMAND}
    RESULT_VARIABLE mpss_RESULT
    COMMAND_ECHO STDOUT
)
if(NOT 0 EQUAL mpss_RESULT)
    message(FATAL_ERROR "iOS simulator configuration failed.")
endif()

set(mpss_SCHEME_FILE
    "${MPSS_BUILD_DIR}/mpss.xcodeproj/xcshareddata/xcschemes/mpss_ios_test_host.xcscheme")
if(NOT EXISTS "${mpss_SCHEME_FILE}")
    message(FATAL_ERROR "Generated host scheme not found: ${mpss_SCHEME_FILE}")
endif()

file(READ "${mpss_SCHEME_FILE}" mpss_SCHEME_CONTENT)
string(FIND "${mpss_SCHEME_CONTENT}"
    "BlueprintName = \"mpss_ios_xctest\"" mpss_TESTABLE_INDEX)
if(-1 EQUAL mpss_TESTABLE_INDEX)
    string(FIND "${mpss_SCHEME_CONTENT}"
        "BlueprintName=\"mpss_ios_xctest\"" mpss_TESTABLE_INDEX)
endif()
if(-1 EQUAL mpss_TESTABLE_INDEX)
    set(mpss_PROJECT_FILE
        "${MPSS_BUILD_DIR}/mpss.xcodeproj/project.pbxproj")
    file(READ "${mpss_PROJECT_FILE}" mpss_PROJECT_CONTENT)
    string(REGEX MATCH
        "([0-9A-F]+) /\\* mpss_ios_xctest \\*/ = \\{[\r\n\t ]*isa = PBXNativeTarget;"
        mpss_XCTEST_TARGET_MATCH "${mpss_PROJECT_CONTENT}")
    if(NOT mpss_XCTEST_TARGET_MATCH)
        message(FATAL_ERROR
            "Could not resolve the XCTest target in ${mpss_PROJECT_FILE}.")
    endif()
    set(mpss_XCTEST_BLUEPRINT_ID "${CMAKE_MATCH_1}")

    string(CONFIGURE [=[
      <TestableReference
         skipped="NO"
         parallelizable="NO">
         <BuildableReference
            BuildableIdentifier="primary"
            BlueprintIdentifier="@mpss_XCTEST_BLUEPRINT_ID@"
            BuildableName="mpss_ios_xctest.xctest"
            BlueprintName="mpss_ios_xctest"
            ReferencedContainer="container:@MPSS_BUILD_DIR@/mpss.xcodeproj"/>
      </TestableReference>
]=] mpss_TESTABLE @ONLY)

    set(mpss_UNMODIFIED_SCHEME_CONTENT "${mpss_SCHEME_CONTENT}")
    string(REPLACE "<Testables/>"
        "<Testables>
${mpss_TESTABLE}      </Testables>"
        mpss_SCHEME_CONTENT "${mpss_SCHEME_CONTENT}")
    if(mpss_SCHEME_CONTENT STREQUAL mpss_UNMODIFIED_SCHEME_CONTENT)
        string(REPLACE "<Testables>
      </Testables>"
            "<Testables>
${mpss_TESTABLE}      </Testables>"
            mpss_SCHEME_CONTENT "${mpss_SCHEME_CONTENT}")
    endif()
    if(mpss_SCHEME_CONTENT STREQUAL mpss_UNMODIFIED_SCHEME_CONTENT)
        message(FATAL_ERROR
            "Generated host scheme could not be updated with the XCTest bundle.")
    endif()
    file(WRITE "${mpss_SCHEME_FILE}" "${mpss_SCHEME_CONTENT}")
endif()

set(mpss_CONTAINER
    "-project;${MPSS_BUILD_DIR}/mpss.xcodeproj"
    "-scheme;mpss_ios_test_host")

set(mpss_DESTINATIONS_OUTPUT "")
foreach(mpss_ATTEMPT RANGE 1 6)
    execute_process(
        COMMAND xcodebuild
            ${mpss_CONTAINER}
            -showdestinations
        RESULT_VARIABLE mpss_RESULT
        OUTPUT_VARIABLE mpss_DESTINATIONS_OUTPUT
        ERROR_VARIABLE mpss_DESTINATIONS_ERROR
    )
    if(0 EQUAL mpss_RESULT)
        string(REGEX MATCH
            "\\{ platform:iOS Simulator, arch:arm64, id:([^,}]+), OS:([^,}]+), name:(iPhone[^}]+) \\}"
            mpss_DESTINATION_MATCH
            "${mpss_DESTINATIONS_OUTPUT}")
        if(mpss_DESTINATION_MATCH)
            break()
        endif()
    endif()
    execute_process(COMMAND "${CMAKE_COMMAND}" -E sleep 5)
endforeach()
if(NOT mpss_DESTINATION_MATCH)
    message(FATAL_ERROR
        "No concrete arm64 iPhone simulator destination found.\n"
        "${mpss_DESTINATIONS_OUTPUT}\n${mpss_DESTINATIONS_ERROR}")
endif()
set(mpss_DESTINATION_ID "${CMAKE_MATCH_1}")
set(mpss_DESTINATION_OS "${CMAKE_MATCH_2}")
set(mpss_DESTINATION_NAME "${CMAKE_MATCH_3}")
string(STRIP "${mpss_DESTINATION_ID}" mpss_DESTINATION_ID)
string(STRIP "${mpss_DESTINATION_OS}" mpss_DESTINATION_OS)
string(STRIP "${mpss_DESTINATION_NAME}" mpss_DESTINATION_NAME)
message(STATUS
    "Selected iOS simulator: ${mpss_DESTINATION_NAME} "
    "(${mpss_DESTINATION_OS}, ${mpss_DESTINATION_ID})")

execute_process(
    COMMAND xcrun simctl boot "${mpss_DESTINATION_ID}"
    RESULT_VARIABLE mpss_BOOT_RESULT
    ERROR_VARIABLE mpss_BOOT_ERROR
)
if(NOT 0 EQUAL mpss_BOOT_RESULT)
    string(FIND "${mpss_BOOT_ERROR}"
        "Unable to boot device in current state: Booted"
        mpss_ALREADY_BOOTED_INDEX)
    if(-1 EQUAL mpss_ALREADY_BOOTED_INDEX)
        message(FATAL_ERROR
            "Failed to boot iOS simulator: ${mpss_BOOT_ERROR}")
    endif()
endif()
execute_process(
    COMMAND xcrun simctl bootstatus "${mpss_DESTINATION_ID}" -b
    RESULT_VARIABLE mpss_RESULT
    COMMAND_ECHO STDOUT
)
if(NOT 0 EQUAL mpss_RESULT)
    message(FATAL_ERROR "iOS simulator did not finish booting.")
endif()

execute_process(
    COMMAND xcodebuild
        ${mpss_CONTAINER}
        -configuration "${MPSS_CONFIGURATION}"
        -destination "platform=iOS Simulator,id=${mpss_DESTINATION_ID}"
        -parallel-testing-enabled NO
        test
    RESULT_VARIABLE mpss_RESULT
    COMMAND_ECHO STDOUT
)
if(NOT 0 EQUAL mpss_RESULT)
    message(FATAL_ERROR "iOS simulator tests failed.")
endif()
