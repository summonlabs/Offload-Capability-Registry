# Test suite. No test carries a timeout: a hanging test is a defect, and every
# wait here synchronises on completed work, a join, end-of-stream or a protocol
# exchange.

function(ocreg_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE OCReg::ocreg)
  target_include_directories(${name} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tools"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src")
  ocreg_apply_warnings(${name})
  target_compile_definitions(${name} PRIVATE
    OCREG_SERVICE_EXE="$<TARGET_FILE:ocreg_service>"
    OCREG_CLI_EXE="$<TARGET_FILE:ocreg_cli>"
    OCREG_CRASH_HELPER_EXE="$<TARGET_FILE:ocreg_crash_helper>")
  if(WIN32)
    target_link_libraries(${name} PRIVATE ws2_32)
  endif()
  add_dependencies(${name} ocreg_cli ocreg_service ocreg_crash_helper)
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

ocreg_add_test(ocreg_test_core test_main.cpp test_core.cpp)
ocreg_add_test(ocreg_test_registry test_main.cpp test_registry.cpp)
ocreg_add_test(ocreg_test_export test_main.cpp test_export.cpp)
ocreg_add_test(ocreg_test_persistence test_main.cpp test_persistence.cpp)
ocreg_add_test(ocreg_test_transport test_main.cpp test_transport.cpp)
ocreg_add_test(ocreg_test_property test_main.cpp test_property.cpp)
ocreg_add_test(ocreg_test_concurrency test_main.cpp test_concurrency.cpp)
ocreg_add_test(ocreg_test_process test_main.cpp test_process.cpp)
