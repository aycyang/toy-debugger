#include "disasm.h"

#include <map>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>

#include "mem.h"

DisasmCache::DisasmCache(const VirtualMemory* vm) : vm(vm) {}

std::vector<std::string> DisasmCache::GetDisasmAround(uintptr_t addr, int padding) {
  std::vector<std::string> result;
  Region region = vm->GetRegionOf(addr);
  auto it = std::find_if(cache.begin(), cache.end(), [&region](std::tuple<Region, std::vector<std::string>> t) {
    return std::get<0>(t) == region;
  });
  if (it != cache.end()) {
    std::vector<std::string>& disasm = std::get<1>(*it);
    // TODO find instruction corresponding to instruction pointer
    return disasm;
  }
  std::vector<std::string> disasm = DisassembleRegion(region);
  cache.push_back(std::make_tuple(region, disasm));
  // TODO find instruction corresponding to instruction pointer
  return disasm;
}

std::vector<std::string> DisasmCache::DisassembleRegion(const Region& region) {
  std::vector<std::string> result;
  // TODO read memory and disassemble it
  return result;
}
