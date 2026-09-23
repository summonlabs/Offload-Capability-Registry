// Offload Capability Registry - test runner entry point.
// Copyright 2026 Summon Software Labs.
#include "test_support.hpp"

int main(int argc, char** argv) {
  const char* suite = (argc > 1) ? argv[1] : "ocreg-tests";
  return ocreg::test::run_all(suite);
}
