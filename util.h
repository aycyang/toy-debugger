#pragma once

#include <vector>
#include <string>

std::vector<std::string> wrapTo(std::string src, size_t width) {
  if (width == 0) {
    return {src};
  }
  std::vector<std::string> result;
  size_t i = 0;
  while ((i + 1) * width < src.size()) {
    result.push_back(src.substr(i * width, width));
    i++;
  }
  result.push_back(src.substr(i * width));
  return result;
}
