#pragma once

#include <sstream>
#include <vector>
#include <cstdint>
#include <unistd.h>

uintptr_t getExecutableMappedPageBasePtr(pid_t pid);

enum class Perms : uint8_t {
  Invalid = 0,
  Read = 1 << 0,
  Write = 1 << 1,
  Execute = 1 << 2,
  Shared = 1 << 3,
  Private = 1 << 4,
};

constexpr Perms operator|(Perms l, Perms r) {
  using T = std::underlying_type_t<Perms>;
  return static_cast<Perms>(static_cast<T>(l) | static_cast<T>(r));
}

constexpr Perms operator&(Perms l, Perms r) {
  using T = std::underlying_type_t<Perms>;
  return static_cast<Perms>(static_cast<T>(l) & static_cast<T>(r));
}

constexpr Perms& operator|=(Perms& l, Perms r) {
  l = l | r;
  return l;
}

constexpr std::string permsToString(const Perms& perms) {
  std::string s = "----";
  if (static_cast<bool>(perms & Perms::Read)) {
    s[0] = 'r';
  }
  if (static_cast<bool>(perms & Perms::Write)) {
    s[1] = 'w';
  }
  if (static_cast<bool>(perms & Perms::Execute)) {
    s[2] = 'x';
  }
  if (static_cast<bool>(perms & Perms::Private)) {
    s[3] = 'p';
  }
  return s;
}

struct Region {
  Region(uintptr_t start, uintptr_t end, Perms perms) : start(start), end(end), perms(perms) {}
  uintptr_t start;
  uintptr_t end;
  Perms perms;
};

class VirtualMemory {
 public:
  VirtualMemory(pid_t pid);
  void Update();
  std::vector<Region> regions;
 private:
  pid_t pid;
};

constexpr std::stringstream&& operator<<(std::stringstream&& ss, const VirtualMemory& vm) {
  for (const Region& region : vm.regions) {
    ss << std::hex << region.start << " - " << region.end << " ";
    ss << std::dec << permsToString(region.perms) << ", ";
  }
  return std::move(ss);
}
