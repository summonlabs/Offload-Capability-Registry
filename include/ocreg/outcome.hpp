// Offload Capability Registry - result and status plumbing.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_OUTCOME_HPP
#define OCREG_OUTCOME_HPP

#include <optional>
#include <string>
#include <utility>

#include "ocreg/reason.hpp"

namespace ocreg {

// The outcome of one operation.
//
// Success is an explicit flag rather than a property of the reason code: an
// operation can succeed while carrying an "unknown" or "already present" code
// (for example a query that legitimately answers "no evidence"), and a refusal
// can carry a code from any category. Deriving success from the code would make
// an explicit unknown look like a success.
struct Status {
  ReasonCode code = ReasonCode::Ok;
  std::string detail{};
  bool failed = false;

  [[nodiscard]] bool ok() const noexcept { return !failed; }

  static Status success(ReasonCode code) noexcept { return Status{code, {}, false}; }
  static Status failure(ReasonCode code, std::string detail = {}) {
    return Status{code, std::move(detail), true};
  }
};

template <class T>
class Outcome {
 public:
  Outcome() = default;
  explicit Outcome(T value) : value_(std::move(value)) {}
  explicit Outcome(Status status) : status_(std::move(status)) {}

  // A success that carries both a value and an outcome code (for example
  // "already present" or "accepted as a superseding revision").
  [[nodiscard]] static Outcome success(T value, ReasonCode reason) {
    Outcome result;
    result.value_ = std::move(value);
    result.status_ = Status::success(reason);
    return result;
  }

  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

  [[nodiscard]] T& value() { return *value_; }
  [[nodiscard]] const T& value() const { return *value_; }
  [[nodiscard]] T&& take() { return std::move(*value_); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }
  [[nodiscard]] ReasonCode reason() const noexcept { return status_.code; }
  [[nodiscard]] const std::string& detail() const noexcept { return status_.detail; }

  [[nodiscard]] T value_or(T fallback) const {
    return value_.has_value() ? *value_ : std::move(fallback);
  }

 private:
  std::optional<T> value_{};
  Status status_{};
};

// A void-capable outcome.
template <>
class Outcome<void> {
 public:
  Outcome() = default;
  explicit Outcome(Status status) : status_(std::move(status)) {}

  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }
  [[nodiscard]] ReasonCode reason() const noexcept { return status_.code; }
  [[nodiscard]] const std::string& detail() const noexcept { return status_.detail; }

 private:
  Status status_{};
};

}  // namespace ocreg

#endif  // OCREG_OUTCOME_HPP
