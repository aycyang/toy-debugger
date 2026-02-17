#pragma once

#include <map>
#include <vector>
#include <string>
#include <cstdint>

#include <Zydis/Zydis.h>

#include "mem.h"

class DisasmCache {
 public:
  DisasmCache(const VirtualMemory* vm);
  std::vector<std::string> GetDisasmAround(uintptr_t addr, int padding);
 private:
  std::vector<std::string> DisassembleRegion(const Region& region);
  const VirtualMemory* vm;
  std::vector<std::tuple<Region, std::vector<std::string>>> cache;
  ZydisDecoder zydis_decoder;
  ZydisFormatter zydis_formatter;
};
