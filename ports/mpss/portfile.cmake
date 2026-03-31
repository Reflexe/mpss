# On Linux, MPSS has no OS-native backend. The YubiKey feature must be enabled.
if(VCPKG_TARGET_IS_LINUX AND NOT "yubikey" IN_LIST FEATURES)
    message(FATAL_ERROR
        "MPSS requires the 'yubikey' feature on Linux because there is no "
        "OS-native backend. Install with: vcpkg install mpss[yubikey]")
endif()

# Android only supports shared libraries.
if(VCPKG_TARGET_IS_ANDROID)
    vcpkg_check_linkage(ONLY_DYNAMIC_LIBRARY)
endif()

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO Microsoft/mpss
    REF "v${VERSION}"
    SHA512 0 # Set to correct hash once released.
    HEAD_REF main
)

if(VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    set(CORE_STATIC ON)
    set(CORE_SHARED OFF)
    set(OPENSSL_STATIC ON)
    set(OPENSSL_SHARED OFF)
else()
    set(CORE_STATIC OFF)
    set(CORE_SHARED ON)
    set(OPENSSL_STATIC OFF)
    set(OPENSSL_SHARED ON)
endif()

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        yubikey    MPSS_BACKEND_YUBIKEY
)

if("openssl" IN_LIST FEATURES)
    set(BUILD_OPENSSL_STATIC ${OPENSSL_STATIC})
    set(BUILD_OPENSSL_SHARED ${OPENSSL_SHARED})
else()
    set(BUILD_OPENSSL_STATIC OFF)
    set(BUILD_OPENSSL_SHARED OFF)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        -DMPSS_BUILD_MPSS_CORE_STATIC=${CORE_STATIC}
        -DMPSS_BUILD_MPSS_CORE_SHARED=${CORE_SHARED}
        -DMPSS_BUILD_MPSS_OPENSSL_STATIC=${BUILD_OPENSSL_STATIC}
        -DMPSS_BUILD_MPSS_OPENSSL_SHARED=${BUILD_OPENSSL_SHARED}
        -DMPSS_BUILD_TESTS=OFF
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

string(REGEX MATCH "^[0-9]+\\.[0-9]+" VERSION_MAJOR_MINOR "${VERSION}")

vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/mpss-${VERSION_MAJOR_MINOR}")

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

file(
    INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
