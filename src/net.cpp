// Offload Capability Registry - internal socket helpers.
// Copyright 2026 Summon Software Labs.
#include "net.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace ocreg::net {
namespace {

#if defined(_WIN32)
std::once_flag g_wsa_once;

[[nodiscard]] bool socket_error_is_interrupted() noexcept { return false; }
#else
[[nodiscard]] bool socket_error_is_interrupted() noexcept {
  return errno == EINTR;
}
#endif

}  // namespace

void ensure_initialised() {
#if defined(_WIN32)
  std::call_once(g_wsa_once, [] {
    WSADATA data{};
    (void)WSAStartup(MAKEWORD(2, 2), &data);
  });
#endif
}

Outcome<Socket> connect_to(const std::string& host, std::uint16_t port) {
  ensure_initialised();
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Outcome<Socket>(Status::failure(ReasonCode::TransportUnavailable, "address lookup failed"));
  }
  Socket socket = kInvalidSocket;
  ReasonCode failure = ReasonCode::TransportUnavailable;
  for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
    const Socket candidate = static_cast<Socket>(
        ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol));
    if (candidate == kInvalidSocket) continue;
    if (::connect(candidate, entry->ai_addr, static_cast<int>(entry->ai_addrlen)) == 0) {
      socket = candidate;
      break;
    }
    close_socket(candidate);
    failure = ReasonCode::TransportClosed;
  }
  ::freeaddrinfo(results);
  if (socket == kInvalidSocket) {
    return Outcome<Socket>(Status::failure(failure, "connect failed"));
  }
  set_no_delay(socket);
  return Outcome<Socket>(socket);
}

Outcome<Socket> listen_on(const std::string& address, std::uint16_t port, std::size_t backlog,
                          bool reuse_address, std::uint16_t& bound_port) {
  ensure_initialised();
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const char* node = address.empty() ? nullptr : address.c_str();
  if (::getaddrinfo(node, service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Outcome<Socket>(Status::failure(ReasonCode::TransportUnavailable, "bind lookup failed"));
  }
  const Socket listener =
      static_cast<Socket>(::socket(results->ai_family, results->ai_socktype, results->ai_protocol));
  if (listener == kInvalidSocket) {
    ::freeaddrinfo(results);
    return Outcome<Socket>(Status::failure(ReasonCode::TransportUnavailable, "socket creation failed"));
  }
  if (reuse_address) {
    const int one = 1;
    (void)::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&one), sizeof(one));
  }
  if (::bind(listener, results->ai_addr, static_cast<int>(results->ai_addrlen)) != 0) {
    ::freeaddrinfo(results);
    close_socket(listener);
    return Outcome<Socket>(Status::failure(ReasonCode::TransportUnavailable, "bind failed"));
  }
  ::freeaddrinfo(results);
  if (::listen(listener, static_cast<int>(backlog)) != 0) {
    close_socket(listener);
    return Outcome<Socket>(Status::failure(ReasonCode::TransportUnavailable, "listen failed"));
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int bound_length = sizeof(bound);
#else
  socklen_t bound_length = sizeof(bound);
#endif
  if (::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
    close_socket(listener);
    return Outcome<Socket>(Status::failure(ReasonCode::TransportUnavailable, "getsockname failed"));
  }
  bound_port = ntohs(bound.sin_port);
  return Outcome<Socket>(listener);
}

Outcome<Socket> accept_one(Socket listener) {
  const Socket accepted = static_cast<Socket>(::accept(listener, nullptr, nullptr));
  if (accepted == kInvalidSocket) {
    return Outcome<Socket>(Status::failure(ReasonCode::TransportClosed, "accept failed"));
  }
  set_no_delay(accepted);
  return Outcome<Socket>(accepted);
}

IoResult recv_exact(Socket socket, std::span<std::uint8_t> buffer) {
  std::size_t received = 0;
  while (received < buffer.size()) {
    const int chunk = ::recv(socket, reinterpret_cast<char*>(buffer.data() + received),
                             static_cast<int>(buffer.size() - received), 0);
    if (chunk == 0) return IoResult::Closed;
    if (chunk < 0) {
      if (socket_error_is_interrupted()) continue;
      return IoResult::Error;
    }
    received += static_cast<std::size_t>(chunk);
  }
  return IoResult::Ok;
}

bool send_all(Socket socket, std::span<const std::uint8_t> buffer) {
  std::size_t sent = 0;
  while (sent < buffer.size()) {
    const int chunk = ::send(socket, reinterpret_cast<const char*>(buffer.data() + sent),
                             static_cast<int>(buffer.size() - sent), 0);
    if (chunk <= 0) {
      if (chunk < 0 && socket_error_is_interrupted()) continue;
      return false;
    }
    sent += static_cast<std::size_t>(chunk);
  }
  return true;
}

void shutdown_both(Socket socket) {
  if (socket == kInvalidSocket) return;
  (void)::shutdown(socket,
#if defined(_WIN32)
                   SD_BOTH
#else
                   SHUT_RDWR
#endif
  );
}

void close_socket(Socket socket) noexcept {
  if (socket == kInvalidSocket) return;
#if defined(_WIN32)
  (void)::closesocket(socket);
#else
  (void)::close(socket);
#endif
}

void set_no_delay(Socket socket) noexcept {
  const int one = 1;
  (void)::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one),
                     sizeof(one));
}

}  // namespace ocreg::net
