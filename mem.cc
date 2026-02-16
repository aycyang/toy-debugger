#include "mem.h"

#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

#include <unistd.h> // pid_t

Perms permsFromString(std::string s) {
  Perms perms = Perms::Invalid;
  if (s[0] == 'r') {
    perms = perms | Perms::Read;
  }
  if (s[1] == 'w') {
    perms = perms | Perms::Write;
  }
  if (s[2] == 'x') {
    perms = perms | Perms::Execute;
  }
  if (s[3] == 'p') {
    perms = perms | Perms::Private;
  }
  return perms;
}

Region parseProcPidMapsLine(std::string line) {
  std::basic_stringstream<char> ss;
  uint64_t start, end;
  char dash;
  std::string perms_str;
  ss << line;
  ss >> std::hex >> start;
  ss >> dash;
  assert(dash == '-');
  ss >> std::hex >> end;
  ss >> perms_str;
  assert(perms_str.size() >= 4);
  Region region(start, end, permsFromString(perms_str));
  return region;
}

VirtualMemory::VirtualMemory(pid_t pid) : pid(pid) {}

void VirtualMemory::Update() {
  std::ifstream maps_file;
  std::basic_stringstream<char> maps_file_path;
  maps_file_path << "/proc/" << pid << "/maps";
  maps_file.open(maps_file_path.str());
  std::string line;
  while (getline(maps_file, line)) {
    regions.emplace_back(parseProcPidMapsLine(line));
  }
}

Region VirtualMemory::GetRegionOf(uintptr_t addr) const {
  auto it = std::find_if(regions.begin(), regions.end(),
    [&addr](const Region& region) {
      return region.Contains(addr);
    }
  );
  return *it;
}
