// Offload Capability Registry - internal socket helpers.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_SRC_NET_HPP
#define OCREG_SRC_NET_HPP

#include <cstdint>
#include <span>
#include <string>

#include "ocreg/outcome.hpp"

namespace ocreg::net {

// A native socket handle. The value -1 is never a valid handle.
using Socket = std::intptr_t;

inline constexpr Socket kInvalidSocket = static_cast<Socket>(-1);

enum class IoResult { Ok, Closed, Error };

// One-time process-wide socket subsystem initialisation. Thread-safe.
void ensure_initialised();

[[nodiscard]] Outcome<Socket> connect_to(const std::string& host, std::uint16_t port);

// Binds and listens. On success 'bound_port' holds the port actually bound,
// which matters when port 0 was requested.
[[nodiscard]] Outcome<Socket> listen_on(const std::string& address, std::uint16_t port,
                                        std::size_t backlog, bool reuse_address,
                                        std::uint16_t& bound_port);

[[nodiscard]] Outcome<Socket> accept_one(Socket listener);

// Blocking reads and writes. There is no timeout: a socket either produces
// data, reaches end of stream or fails.
[[nodiscard]] IoResult recv_exact(Socket socket, std::span<std::uint8_t> buffer);
[[nodiscard]] bool send_all(Socket socket, std::span<const std::uint8_t> buffer);

// Unblocks any thread blocked in recv_exact for this socket.
void shutdown_both(Socket socket);
void close_socket(Socket socket) noexcept;

void set_no_delay(Socket socket) noexcept;

}  // namespace ocreg::net

#endif  // OCREG_SRC_NET_HPP
