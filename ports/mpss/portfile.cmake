# On Linux, MPSS has no OS-native backend. The YubiKey feature must be enabled.
if(VCPKG_TARGET_IS_LINUX AND NOT "yubikey" IN_LIST FEATURES)
    message(FATAL_ERROR
        "MPSS requires the 'yubikey' feature on Linux because there is no "
        "OS-native backend. Install with: vcpkg install mpss[yubikey]")
endif()

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO Microsoft/mpss
    REF "v${VERSION}"
    SHA512 0 # Set to correct hash once released.
    HEAD_REF main
)

# Pick the matching CMake option per linkage; the unused option in each
# pair (STATIC vs SHARED) defaults to NO from the option() declarations in
# the root CMakeLists.txt and does not need to be set explicitly.
if(VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    set(CORE_OPTION    "-DMPSS_BUILD_MPSS_CORE_STATIC=ON")
    set(OPENSSL_OPTION "-DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON")
else()
    set(CORE_OPTION    "-DMPSS_BUILD_MPSS_CORE_SHARED=ON")
    set(OPENSSL_OPTION "-DMPSS_BUILD_MPSS_OPENSSL_SHARED=ON")
endif()

# The 'openssl' feature is handled manually rather than via
# vcpkg_check_features because it controls one of two CMake options
# (MPSS_BUILD_MPSS_OPENSSL_STATIC / _SHARED) keyed on the triplet's
# linkage. vcpkg_check_features is one-feature-to-one-option only.
if(NOT "openssl" IN_LIST FEATURES)
    set(OPENSSL_OPTION "")
endif()

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        yubikey    MPSS_BACKEND_YUBIKEY
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        ${CORE_OPTION}
        ${OPENSSL_OPTION}
        -DMPSS_BUILD_TESTS=OFF
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/mpss")

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

file(
    INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
