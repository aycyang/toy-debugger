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
  std::map<uintptr_t, std::string> DisassembleRegion(const Region& region);
  std::string FormatInstruction(std::string prefix, uintptr_t addr, std::string disasm);
  const VirtualMemory* vm;
  std::map<Region, std::map<uintptr_t, std::string>> cache;
  ZydisDecoder zydis_decoder;
  ZydisFormatter zydis_formatter;
};
