#include "disasm.h"

#include <map>
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>

#include <Zydis/Zydis.h>

#include "mem.h"

DisasmCache::DisasmCache(const VirtualMemory* vm) : vm(vm) {
  ZydisDecoderInit(&zydis_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&zydis_formatter, ZYDIS_FORMATTER_STYLE_ATT);
}

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
  std::vector<std::tuple<ZydisDecodedInstruction, std::array<ZydisDecodedOperand,10>>> instructions;
  uintptr_t addr = region.start;
  std::array<uint64_t, 2> words;
  words[0] = vm->Read(addr);
  words[1] = vm->Read(addr + 8);
  int i = 0;
  while (addr <= region.end) {
    ZydisDecodedInstruction instruction;
    std::array<ZydisDecodedOperand, 10> operands;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydis_decoder,
      words.data(), 16, &instruction, operands.data()))) {
      break;
    }
    instructions.push_back(make_tuple(instruction, operands));

    addr += instruction.length;
    words[0] = vm->Read(addr);
    words[1] = vm->Read(addr + 8);
    i++;
  }
  for (const auto& [instr, operands] : instructions) {
    char buffer[256];
    ZydisFormatterFormatInstruction(&zydis_formatter, &instr, operands.data(), ZYDIS_MAX_OPERAND_COUNT_VISIBLE, buffer, sizeof(buffer), addr, ZYAN_NULL);
    result.push_back(std::string(buffer));
  }
  return result;
}
