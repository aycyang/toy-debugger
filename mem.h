#pragma once

#include <sstream>
#include <vector>
#include <cstdint>
#include <unistd.h>

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

class Region {
 public:
  Region(uintptr_t start, uintptr_t end, Perms perms) : start(start), end(end), perms(perms) {}
  bool Contains(uintptr_t addr) const { return start <= addr && addr <= end; }
  uintptr_t start;
  uintptr_t end;
  Perms perms;
};

class VirtualMemory {
 public:
  VirtualMemory(pid_t pid);
  void Update();
  Region GetRegionOf(uintptr_t addr) const;
  uint64_t Read(uintptr_t addr) const;
  std::vector<Region> regions;
 private:
  pid_t pid;
};

constexpr bool operator==(Region& l, Region& r) {
  return l.start == r.start && l.end == r.end && l.perms == r.perms;
}

constexpr bool operator<(const Region& l, const Region& r) {
  return l.start < r.start;
}
