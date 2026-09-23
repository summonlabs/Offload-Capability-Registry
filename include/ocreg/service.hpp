// Offload Capability Registry - service surface.
// Copyright 2026 Summon Software Labs.
//
// The service owns a listening socket and a bounded worker pool. It applies
// requests to a Registry and returns registry answers. It performs no
// scheduling, no device programming and no authority granting.
#ifndef OCREG_SERVICE_HPP
#define OCREG_SERVICE_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "ocreg/outcome.hpp"
#include "ocreg/protocol.hpp"
#include "ocreg/registry.hpp"

namespace ocreg {

class Service {
 public:
  Service(Registry& registry, ServerOptions options);
  ~Service();

  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  // Binds, listens and starts accepting. Returns the bound port (useful when
  // options.port was zero). Never blocks.
  Outcome<std::uint16_t> start();

  // Blocks until a Shutdown request has been served, or until stop() has been
  // called. This is a real condition-variable wait: there is no polling and no
  // timeout.
  void wait_for_shutdown();

  // True once a Shutdown request has been served.
  [[nodiscard]] bool shutdown_requested() const noexcept;

  // Stops accepting, completes in-flight requests, joins every worker and
  // closes the listener. Idempotent and safe to call repeatedly.
  void stop();

  [[nodiscard]] bool running() const noexcept;
  [[nodiscard]] std::uint16_t port() const noexcept;
  [[nodiscard]] std::uint64_t requests_served() const noexcept;
  [[nodiscard]] std::uint64_t connections_accepted() const noexcept;
  [[nodiscard]] std::uint64_t connections_refused() const noexcept;
  [[nodiscard]] std::uint64_t frames_rejected() const noexcept;
  [[nodiscard]] std::uint64_t bytes_read() const noexcept;
  [[nodiscard]] std::uint64_t bytes_written() const noexcept;
  [[nodiscard]] std::uint64_t shutdown_requests() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ocreg

#endif  // OCREG_SERVICE_HPP
