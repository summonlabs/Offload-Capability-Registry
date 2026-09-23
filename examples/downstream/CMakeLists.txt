cmake_minimum_required(VERSION 3.21)

# An independent downstream project. It consumes the installed package only:
# it does not add the registry source tree, does not know the build tree, and
# inherits none of the upstream warning configuration.
project(OCRegDownstreamConsumer
  VERSION 1.0.0
  DESCRIPTION "Independent consumer of the Offload Capability Registry package"
  LANGUAGES CXX)

find_package(OCReg 1.0 REQUIRED CONFIG)

add_executable(ocreg_consumer main.cpp)
target_link_libraries(ocreg_consumer PRIVATE OCReg::ocreg)
set_target_properties(ocreg_consumer PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF)

# The consumer compiles with its own strict settings to prove that the package
# exports usable headers and a usable library without leaking upstream flags.
if(MSVC)
  target_compile_options(ocreg_consumer PRIVATE /W4 /WX /permissive- /utf-8 /EHsc)
else()
  target_compile_options(ocreg_consumer PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

enable_testing()
add_test(NAME ocreg_consumer COMMAND ocreg_consumer)
set_tests_properties(ocreg_consumer PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

message(STATUS "OCReg ${OCReg_VERSION} found at ${OCReg_DIR}")
