// Offload Capability Registry - test support.
// Copyright 2026 Summon Software Labs.
//
// A deliberately small harness with no third-party dependency and, critically,
// no timeouts anywhere: every wait in the suite synchronises on completed
// work, a joined thread, an end-of-stream or a protocol exchange.
#ifndef OCREG_TESTS_TEST_SUPPORT_HPP
#define OCREG_TESTS_TEST_SUPPORT_HPP

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace ocreg::test {

using TestFn = void (*)();

struct TestCase {
  const char* name;
  TestFn fn;
};

[[nodiscard]] inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

struct Registrar {
  Registrar(const char* name, TestFn fn) { registry().push_back(TestCase{name, fn}); }
};

struct Failure {
  std::string test;
  std::string expression;
  const char* file;
  int line;
  std::string detail;
};

[[nodiscard]] inline std::vector<Failure>& failures() {
  static std::vector<Failure> entries;
  return entries;
}

inline std::string& current_test() {
  static std::string name;
  return name;
}

inline void record_failure(const char* expression, const char* file, int line,
                           const std::string& detail) {
  failures().push_back(Failure{current_test(), expression, file, line, detail});
  std::cerr << "  FAIL " << current_test() << " : " << expression << " at " << file << ':'
            << line;
  if (!detail.empty()) std::cerr << " [" << detail << ']';
  std::cerr << '\n';
}

template <class A, class B>
void check_equal(const A& lhs, const B& rhs, const char* expression, const char* file, int line) {
  if (!(lhs == rhs)) {
    std::ostringstream detail;
    detail << "left=" << lhs << " right=" << rhs;
    record_failure(expression, file, line, detail.str());
  }
}

[[nodiscard]] inline int run_all(const char* suite) {
  std::size_t failed = 0;
  for (const auto& test : registry()) {
    current_test() = test.name;
    std::cout << "[ RUN  ] " << test.name << std::endl;
    const std::size_t before = failures().size();
    test.fn();
    if (failures().size() != before) ++failed;
    std::cout << "[ DONE ] " << test.name << std::endl;
  }
  std::cout << suite << ": " << registry().size() << " test(s), " << failed << " failing, "
            << failures().size() << " assertion failure(s)\n";
  return failed == 0 ? 0 : 1;
}

// --- Filesystem helpers -----------------------------------------------------

[[nodiscard]] inline std::filesystem::path temp_root() {
  const std::filesystem::path root = std::filesystem::current_path() / "ocreg-test-tmp";
  std::error_code error;
  std::filesystem::create_directories(root, error);
  return root;
}

[[nodiscard]] inline std::filesystem::path fresh_dir(const std::string& name) {
  const std::filesystem::path path = temp_root() / name;
  std::error_code error;
  std::filesystem::remove_all(path, error);
  std::filesystem::create_directories(path, error);
  return path;
}

[[nodiscard]] inline bool write_file(const std::filesystem::path& path, std::string_view text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream.write(text.data(), static_cast<std::streamsize>(text.size()));
  return stream.good();
}

[[nodiscard]] inline bool read_file(const std::filesystem::path& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return false;
  out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
  return true;
}

[[nodiscard]] inline std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::vector<std::uint8_t> bytes;
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return bytes;
  char c = 0;
  while (stream.get(c)) bytes.push_back(static_cast<std::uint8_t>(c));
  return bytes;
}

inline bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return stream.good();
}

inline void append_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::app);
  if (!stream) return;
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

// --- Deterministic pseudo random generator ----------------------------------

// A seeded xorshift generator. Deterministic across platforms and standard
// libraries, which is what property and differential tests require.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  [[nodiscard]] std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  [[nodiscard]] std::uint32_t below(std::uint32_t bound) {
    return bound == 0 ? 0 : static_cast<std::uint32_t>(next() % bound);
  }

  [[nodiscard]] bool coin() { return (next() & 1ull) != 0; }

 private:
  std::uint64_t state_;
};

// --- Child processes --------------------------------------------------------

// A real independent OS process with a captured standard output stream. Reads
// block; there is no polling and no timeout. A child that never produces the
// expected line is a defect, not a flaky test.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { close(); }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  [[nodiscard]] static std::unique_ptr<ChildProcess> spawn(const std::vector<std::string>& argv) {
    auto child = std::unique_ptr<ChildProcess>(new ChildProcess());
#if defined(_WIN32)
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (!::CreatePipe(&read_end, &write_end, &attributes, 0)) return nullptr;
    ::SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

    std::string command;
    for (const auto& token : argv) {
      if (!command.empty()) command.push_back(' ');
      command.push_back('"');
      command += token;
      command.push_back('"');
    }
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_end;
    startup.hStdError = write_end;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION info{};
    std::vector<char> mutable_command(command.begin(), command.end());
    mutable_command.push_back('\0');
    if (!::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, 0, nullptr,
                          nullptr, &startup, &info)) {
      ::CloseHandle(read_end);
      ::CloseHandle(write_end);
      return nullptr;
    }
    ::CloseHandle(write_end);
    ::CloseHandle(info.hThread);
    child->process_ = info.hProcess;
    child->pipe_ = read_end;
#else
    int fds[2] = {-1, -1};
    if (::pipe(fds) != 0) return nullptr;
    std::vector<char*> raw;
    for (const auto& token : argv) raw.push_back(const_cast<char*>(token.c_str()));
    raw.push_back(nullptr);
    pid_t pid = 0;
    if (::posix_spawn(&pid, raw[0], nullptr, nullptr, raw.data(), environ) != 0) {
      ::close(fds[0]);
      ::close(fds[1]);
      return nullptr;
    }
    ::close(fds[1]);
    child->pid_ = pid;
    child->pipe_ = fds[0];
#endif
    child->open_ = true;
    return child;
  }

  // Blocking read of one line. Returns false at end of stream.
  [[nodiscard]] bool read_line(std::string& line) {
    line.clear();
    if (!open_ || !pipe_valid()) return false;
    for (;;) {
      char c = 0;
#if defined(_WIN32)
      DWORD read = 0;
      if (!::ReadFile(pipe_, &c, 1, &read, nullptr) || read == 0) return false;
#else
      const ssize_t read = ::read(static_cast<int>(pipe_), &c, 1);
      if (read <= 0) return false;
#endif
      if (c == '\n') return true;
      if (c != '\r') line.push_back(c);
    }
  }

  // Waits for the process to exit. This is a real wait on the process handle,
  // never a timeout.
  [[nodiscard]] int wait() {
    if (!open_) return exit_code_;
#if defined(_WIN32)
    ::WaitForSingleObject(process_, INFINITE);
    DWORD code = 0;
    ::GetExitCodeProcess(process_, &code);
    exit_code_ = static_cast<int>(code);
#else
    int status = 0;
    (void)::waitpid(pid_, &status, 0);
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
#endif
    return exit_code_;
  }

  void close() {
    if (!open_) return;
#if defined(_WIN32)
    if (pipe_ != nullptr) ::CloseHandle(pipe_);
    if (process_ != nullptr) ::CloseHandle(process_);
    pipe_ = nullptr;
    process_ = nullptr;
#else
    if (pipe_ >= 0) ::close(pipe_);
    pipe_ = -1;
    pid_ = -1;
#endif
    open_ = false;
  }

 private:
  [[nodiscard]] bool pipe_valid() const noexcept {
#if defined(_WIN32)
    return pipe_ != nullptr;
#else
    return pipe_ >= 0;
#endif
  }

#if defined(_WIN32)
  HANDLE process_ = nullptr;
  HANDLE pipe_ = nullptr;
#else
  int pipe_ = -1;
  int pid_ = -1;
#endif
  int exit_code_ = -1;
  bool open_ = false;
};

// --- Small assertion helpers -----------------------------------------------

template <class T>
[[nodiscard]] std::string describe(const T& value) {
  std::ostringstream stream;
  stream << value;
  return stream.str();
}

}  // namespace ocreg::test

#define OCREG_TEST(name)                                                            \
  static void name();                                                               \
  static const ::ocreg::test::Registrar ocreg_registrar_##name(#name, &name);       \
  static void name()

#define CHECK(expression)                                                           \
  do {                                                                              \
    if (!(expression)) {                                                            \
      ::ocreg::test::record_failure(#expression, __FILE__, __LINE__, std::string());\
    }                                                                               \
  } while (false)

#define CHECK_MSG(expression, message)                                              \
  do {                                                                              \
    if (!(expression)) {                                                            \
      ::ocreg::test::record_failure(#expression, __FILE__, __LINE__, (message));    \
    }                                                                               \
  } while (false)

#define CHECK_EQ(lhs, rhs)                                                          \
  ::ocreg::test::check_equal((lhs), (rhs), #lhs " == " #rhs, __FILE__, __LINE__)

#define REQUIRE(expression)                                                         \
  do {                                                                              \
    if (!(expression)) {                                                            \
      ::ocreg::test::record_failure(#expression " (required)", __FILE__, __LINE__,  \
                                    std::string());                                 \
      return;                                                                       \
    }                                                                               \
  } while (false)

#define REQUIRE_MSG(expression, message)                                            \
  do {                                                                              \
    if (!(expression)) {                                                            \
      ::ocreg::test::record_failure(#expression " (required)", __FILE__, __LINE__,  \
                                    (message));                                     \
      return;                                                                       \
    }                                                                               \
  } while (false)

#endif  // OCREG_TESTS_TEST_SUPPORT_HPP
