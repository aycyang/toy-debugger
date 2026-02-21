#include "log.h"

#include <iostream>
#include <fstream>

namespace {
  std::ofstream kOutFileStream("log.txt");
}  // namespace

ScopedOutStream Log(LogLevel level) {
  ScopedOutStream os(kOutFileStream);
  switch (level) {
    case LogLevel::Debug:
      os << "[DEBUG] ";
    break;
    case LogLevel::Info:
      os << "[INFO] ";
    break;
  }
  return os;
}

ScopedOutStream::ScopedOutStream(std::ostream& os) : os(os) {}
ScopedOutStream::~ScopedOutStream() {
  os << std::endl;
}
