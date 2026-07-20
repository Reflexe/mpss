# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Collect the source files for the shared attestation verifier. In Stage 1 this library is
# built in-tree and consumed only by the test suite; install/export is deferred to a later
# stage (see docs/attestation-design.md, staged rollout).
list(APPEND mpss_attest_verify_SOURCE_FILES
    "${CMAKE_CURRENT_LIST_DIR}/attestation_verifier.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/windows_tpm_claim_verifier.cpp"
)

# Update the source list in the parent scope.
set(mpss_attest_verify_SOURCE_FILES ${mpss_attest_verify_SOURCE_FILES} PARENT_SCOPE)
