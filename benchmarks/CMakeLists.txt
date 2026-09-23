add_executable(ocreg_bench_registry bench_registry.cpp)
target_link_libraries(ocreg_bench_registry PRIVATE OCReg::ocreg)
ocreg_apply_warnings(ocreg_bench_registry)

add_executable(ocreg_bench_persistence bench_persistence.cpp)
target_link_libraries(ocreg_bench_persistence PRIVATE OCReg::ocreg)
ocreg_apply_warnings(ocreg_bench_persistence)

add_executable(ocreg_bench_transport bench_transport.cpp)
target_link_libraries(ocreg_bench_transport PRIVATE OCReg::ocreg)
target_include_directories(ocreg_bench_transport PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
ocreg_apply_warnings(ocreg_bench_transport)
