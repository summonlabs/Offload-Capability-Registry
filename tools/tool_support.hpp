// Offload Capability Registry - shared helpers for the shipped tools.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_TOOLS_TOOL_SUPPORT_HPP
#define OCREG_TOOLS_TOOL_SUPPORT_HPP

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ocreg/json.hpp"
#include "ocreg/registry.hpp"

namespace ocreg::tools {

struct Arguments {
  std::string command{};
  std::vector<std::pair<std::string, std::string>> options{};
  std::vector<std::string> positional{};

  [[nodiscard]] std::optional<std::string> get(std::string_view name) const {
    for (const auto& [key, value] : options) {
      if (key == name) return value;
    }
    return std::nullopt;
  }

  [[nodiscard]] std::string get_or(std::string_view name, std::string fallback) const {
    const auto found = get(name);
    return found.has_value() ? *found : std::move(fallback);
  }

  [[nodiscard]] bool flag(std::string_view name) const { return get(name).has_value(); }
};

[[nodiscard]] inline Arguments parse_arguments(int argc, char** argv) {
  Arguments arguments;
  for (int index = 1; index < argc; ++index) {
    const std::string_view token(argv[index]);
    if (token.rfind("--", 0) == 0) {
      const std::size_t equals = token.find('=');
      if (equals != std::string_view::npos) {
        arguments.options.emplace_back(std::string(token.substr(2, equals - 2)),
                                       std::string(token.substr(equals + 1)));
      } else if (index + 1 < argc && std::string_view(argv[index + 1]).rfind("--", 0) != 0) {
        arguments.options.emplace_back(std::string(token.substr(2)), std::string(argv[++index]));
      } else {
        arguments.options.emplace_back(std::string(token.substr(2)), std::string());
      }
    } else if (arguments.command.empty()) {
      arguments.command = std::string(token);
    } else {
      arguments.positional.emplace_back(token);
    }
  }
  return arguments;
}

[[nodiscard]] inline bool read_text_file(const std::string& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return false;
  out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
  return true;
}

[[nodiscard]] inline bool write_text_file(const std::string& path, std::string_view text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream.write(text.data(), static_cast<std::streamsize>(text.size()));
  return stream.good();
}

inline void print_error(ReasonCode reason, const std::string& detail) {
  std::cerr << "error: " << to_string(reason);
  if (!detail.empty()) std::cerr << ": " << detail;
  std::cerr << '\n';
}

[[nodiscard]] inline std::uint64_t parse_unsigned(const std::string& text, bool& ok) {
  ok = false;
  if (text.empty() || text.size() > 20) return 0;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return 0;
    value = value * 10u + static_cast<std::uint64_t>(c - '0');
  }
  ok = true;
  return value;
}

}  // namespace ocreg::tools

#endif  // OCREG_TOOLS_TOOL_SUPPORT_HPP
