#include "disasm.h"

#include <format>
#include <map>
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>

#include <Zydis/Zydis.h>

#include "mem.h"

namespace {
std::string formatInstruction(std::string prefix, uintptr_t addr, std::string disasm) {
  std::basic_stringstream<char> ss;
  ss << prefix;
  ss << std::format("0x{:x}", addr) << "  ";
  ss << disasm;
  return ss.str();
}
}  // namespace

DisasmCache::DisasmCache(const VirtualMemory* vm) : vm(vm) {
  ZydisDecoderInit(&zydis_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&zydis_formatter, ZYDIS_FORMATTER_STYLE_ATT);
}

std::vector<std::string> DisasmCache::GetDisasmAround(uintptr_t addr, int padding) {
  std::vector<std::string> result;
  Region region = vm->GetRegionOf(addr);
  auto& disasm = cache[region];
  if (disasm.empty()) {
    disasm = DisassembleRegion(region);
  }
  auto it = disasm.find(addr);
  int b = 0;
  for (b = 0; b < padding; b++) {
    if (it == disasm.begin()) break;
    it--;
  }
  for (int i = 0; i < b; i++) {
    result.push_back(formatInstruction("  ", it->first, it->second));
    it++;
  }
  result.push_back(formatInstruction("> ", it->first, it->second));
  it++;
  for (int i = 0; i < padding; i++) {
    if (it == disasm.end()) break;
    result.push_back(formatInstruction("  ", it->first, it->second));
    it++;
  }
  return result;
}

std::map<uintptr_t, std::string> DisasmCache::DisassembleRegion(const Region& region) {
  std::vector<std::string> result;
  std::vector<std::tuple<ZydisDecodedInstruction, std::array<ZydisDecodedOperand,10>>> instructions;
  std::map<uintptr_t, std::string> formatted_disasm;
  // The longest possible x86 instruction is 15 bytes.
  // Two 64-bit unsigned integers should cover it.
  std::array<uint64_t, 2> words;
  uintptr_t addr = region.start;
  while (addr <= region.end) {
    words[0] = vm->Read(addr);
    words[1] = vm->Read(addr + 8);

    ZydisDecodedInstruction instruction;
    std::array<ZydisDecodedOperand, 10> operands;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydis_decoder, words.data(), 16,
      &instruction, operands.data()))) {
      break;
    }

    char buffer[256];
    ZydisFormatterFormatInstruction(&zydis_formatter, &instruction, operands.data(),
      ZYDIS_MAX_OPERAND_COUNT_VISIBLE, buffer, sizeof(buffer), addr, ZYAN_NULL);
    formatted_disasm[addr] = buffer;

    addr += instruction.length;
  }
  return formatted_disasm;
}
