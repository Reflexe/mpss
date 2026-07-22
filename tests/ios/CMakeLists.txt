# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(FATAL_ERROR "The iOS test host can only be built for iOS.")
endif()
if(NOT CMAKE_GENERATOR STREQUAL "Xcode")
    message(FATAL_ERROR "The iOS test host requires the Xcode generator.")
endif()
if(NOT TARGET ${mpss_TARGET})
    message(FATAL_ERROR "The iOS test host requires the MPSS core target.")
endif()

set(mpss_IOS_TEST_HOST mpss_ios_test_host)
set(mpss_IOS_XCTEST_TARGET mpss_ios_xctest)

add_executable(${mpss_IOS_TEST_HOST} MACOSX_BUNDLE
    main.m
)
set_target_properties(${mpss_IOS_TEST_HOST} PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME "MPSS iOS Tests"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.microsoft.research.mpss.tests"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/Info.plist.in"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS
        "${CMAKE_CURRENT_LIST_DIR}/mpss_ios_test_host.entitlements"
    XCODE_ATTRIBUTE_INFOPLIST_KEY_UIApplicationSceneManifest_Generation YES
    XCODE_ATTRIBUTE_INFOPLIST_KEY_UILaunchScreen_Generation YES
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.microsoft.research.mpss.tests"
    XCODE_GENERATE_SCHEME YES
)
target_link_libraries(${mpss_IOS_TEST_HOST} PRIVATE
    "-framework UIKit"
)

add_library(mpss_ios_tests OBJECT
    ${mpss_TESTS_FILES}
)
target_link_libraries(mpss_ios_tests PRIVATE
    GTest::gtest
    ${mpss_TARGET}
)
if(TARGET ${mpss_openssl_TARGET})
    target_link_libraries(mpss_ios_tests PRIVATE ${mpss_openssl_TARGET})
endif()

add_library(${mpss_IOS_XCTEST_TARGET} MODULE
    mpss_xctest.mm
    $<TARGET_OBJECTS:mpss_ios_tests>
)
set_target_properties(${mpss_IOS_XCTEST_TARGET} PROPERTIES
    BUNDLE TRUE
    BUNDLE_EXTENSION xctest
    LIBRARY_OUTPUT_DIRECTORY
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>"
    XCODE_PRODUCT_TYPE "com.apple.product-type.bundle.unit-test"
    XCODE_ATTRIBUTE_BUNDLE_LOADER "$<TARGET_FILE:${mpss_IOS_TEST_HOST}>"
    XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED YES
    XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED NO
    XCODE_ATTRIBUTE_GENERATE_INFOPLIST_FILE YES
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.microsoft.research.mpss.tests.xctest"
    XCODE_ATTRIBUTE_TEST_HOST "$<TARGET_FILE:${mpss_IOS_TEST_HOST}>"
)
target_link_libraries(${mpss_IOS_XCTEST_TARGET} PRIVATE
    GTest::gtest
    ${mpss_TARGET}
    "-framework XCTest"
)
if(TARGET ${mpss_openssl_TARGET})
    target_compile_definitions(${mpss_IOS_XCTEST_TARGET} PRIVATE
        MPSS_IOS_EXPECTED_FAILED=0
        MPSS_IOS_EXPECTED_PASSED=71
        MPSS_IOS_EXPECTED_SKIPPED=2
        MPSS_IOS_EXPECTED_TOTAL=73
    )
    target_link_libraries(${mpss_IOS_XCTEST_TARGET} PRIVATE ${mpss_openssl_TARGET})
endif()
add_dependencies(${mpss_IOS_XCTEST_TARGET} ${mpss_IOS_TEST_HOST})
