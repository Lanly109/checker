# Keep "windows" in the triplet name so vcpkg-rs selects .lib files.
set(VCPKG_TARGET_ARCHITECTURE x86)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_BUILD_TYPE release)

# vcpkg clears most environment variables for port builds. Keep the host
# pkg-config override so it does not acquire its obsolete private MSYS2.
set(VCPKG_ENV_PASSTHROUGH PKG_CONFIG)

# Use the same C++ runtime and SDK as the Rust link step.
set(VCPKG_PLATFORM_TOOLSET v142)
set(VCPKG_PLATFORM_TOOLSET_VERSION 14.29)
set(VCPKG_CMAKE_SYSTEM_VERSION 10.0.19041.0)

set(VCPKG_C_FLAGS "/D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /DNTDDI_VERSION=0x06010000")
set(VCPKG_CXX_FLAGS "${VCPKG_C_FLAGS}")
