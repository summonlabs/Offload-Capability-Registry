// Offload Capability Registry - benchmark support.
// Copyright 2026 Summon Software Labs.
//
// Every benchmark measures completed work and asserts that the expected number
// of operations actually finished. Nothing here measures enqueue latency.
#ifndef OCREG_BENCHMARKS_BENCH_SUPPORT_HPP
#define OCREG_BENCHMARKS_BENCH_SUPPORT_HPP

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace ocreg::bench {

class Timer {
 public:
  Timer() : start_(std::chrono::steady_clock::now()) {}

  [[nodiscard]] double seconds() const {
    const auto finish = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(finish - start_).count();
  }

 private:
  std::chrono::steady_clock::time_point start_;
};

inline void report(const char* name, std::uint64_t completed, double seconds, const char* unit) {
  const double per_operation = completed == 0 ? 0.0 : (seconds * 1e9) / static_cast<double>(completed);
  std::printf("%-46s %10llu %-14s %10.3f s %12.1f ns/%s\n", name,
              static_cast<unsigned long long>(completed), unit, seconds, per_operation, unit);
  std::fflush(stdout);
}

inline void require(bool condition, const char* message) {
  if (!condition) {
    std::fprintf(stderr, "benchmark assertion failed: %s\n", message);
    std::exit(1);
  }
}

}  // namespace ocreg::bench

#endif  // OCREG_BENCHMARKS_BENCH_SUPPORT_HPP
