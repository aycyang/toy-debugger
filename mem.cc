#include "mem.h"

#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

#include <unistd.h> // pid_t

// TODO adapt this code to find all mapped pages with ELFs
// TODO write a function that takes a mapped ELF and 
uintptr_t getExecutableMappedPageBasePtr(pid_t pid) {
  std::ifstream maps_file;
  std::basic_stringstream<char> maps_file_path;
  maps_file_path << "/proc/" << pid << "/maps";
  maps_file.open(maps_file_path.str());
  
  // TODO Naive assumption: the first hex number in the maps file is the base
  // address of the page where the executable is mapped.
  uintptr_t base_ptr;
  maps_file >> std::hex >> base_ptr;

  return base_ptr;
}

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
