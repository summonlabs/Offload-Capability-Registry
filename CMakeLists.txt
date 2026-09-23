cmake_minimum_required(VERSION 3.21)

project(OffloadCapabilityRegistry
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral offload capability registry runtime"
  HOMEPAGE_URL "https://github.com/summonlabs/Offload-Capability-Registry"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(OCREG_BUILD_TOOLS "Build the ocreg CLI and service executables" ON)
option(OCREG_BUILD_TESTS "Build the test suite" ON)
option(OCREG_BUILD_BENCHMARKS "Build the benchmark executables" ON)
option(OCREG_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(OCREG_ENABLE_ASAN "Build with AddressSanitizer (MSVC /fsanitize=address)" OFF)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(OCREG_ENABLE_ASAN AND MSVC)
  # MSVC requires the dynamic ASan runtime; /RTC1 is incompatible with it.
  add_compile_options(/fsanitize=address)
  add_link_options(/fsanitize=address)
  string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

include(OCRegWarnings)

add_library(ocreg)
add_library(OCReg::ocreg ALIAS ocreg)

target_sources(ocreg
  PRIVATE
    src/net.cpp
    src/codec.cpp
    src/semver.cpp
    src/hash.cpp
    src/json.cpp
    src/units.cpp
    src/catalog.cpp
    src/reason.cpp
    src/name.cpp
    src/evidence.cpp
    src/registry.cpp
    src/compat.cpp
    src/persist.cpp
    src/export.cpp
    src/protocol.cpp
    src/client.cpp
    src/service.cpp)

target_include_directories(ocreg
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>")

target_compile_features(ocreg PUBLIC cxx_std_20)
set_target_properties(ocreg PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  EXPORT_NAME ocreg)

ocreg_apply_warnings(ocreg)

if(WIN32)
  target_compile_definitions(ocreg PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(ocreg PRIVATE ws2_32)
endif()

# The warning configuration is first-party only; the exported target must never
# leak flags into a downstream project.
target_include_directories(ocreg PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

if(OCREG_BUILD_TOOLS)
  add_executable(ocreg_cli tools/ocreg_cli.cpp)
  target_link_libraries(ocreg_cli PRIVATE OCReg::ocreg)
  target_include_directories(ocreg_cli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
  ocreg_apply_warnings(ocreg_cli)

  add_executable(ocreg_service tools/ocreg_service.cpp)
  target_link_libraries(ocreg_service PRIVATE OCReg::ocreg)
  target_include_directories(ocreg_service PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
  ocreg_apply_warnings(ocreg_service)

  add_executable(ocreg_crash_helper tools/ocreg_crash_helper.cpp)
  target_link_libraries(ocreg_crash_helper PRIVATE OCReg::ocreg)
  target_include_directories(ocreg_crash_helper PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
  ocreg_apply_warnings(ocreg_crash_helper)
endif()

if(OCREG_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(OCREG_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS ocreg
  EXPORT OCRegTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(OCREG_BUILD_TOOLS)
  install(TARGETS ocreg_cli ocreg_service
    EXPORT OCRegTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/ocreg DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT OCRegTargets
  FILE OCRegTargets.cmake
  NAMESPACE OCReg::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OCReg)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/OCRegConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/OCRegConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OCReg)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/OCRegConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
  ARCH_INDEPENDENT)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/OCRegConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/OCRegConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OCReg)

install(FILES LICENSE README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/OffloadCapabilityRegistry
  OPTIONAL)
