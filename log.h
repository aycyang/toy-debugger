#pragma once

#include <iostream>
#include <streambuf>
#include <fstream>

#define DLOG() Log(LogLevel::Debug)
#define LOG() Log(LogLevel::Info)

class ScopedOutStream {
 public:
  ScopedOutStream(std::ostream& os);
  ~ScopedOutStream();

  template <typename T>
  ScopedOutStream& operator<<(const T& t) {
    os << t;
    return *this;
  }
 private:
  std::ostream& os;
};

enum class LogLevel {
  Debug,
  Info,
};

ScopedOutStream Log(LogLevel level);

