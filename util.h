#pragma once

#include <vector>
#include <string>

std::vector<std::string> split(const std::string& src, const std::string& delimiter = "\n") {
  std::vector<std::string> results;
  std::string::size_type i = src.find(delimiter);
  if (i == std::string::npos) {
    results.push_back(src);
    return results;
  }
  std::string::size_type start = 0;
  do {
    results.push_back(src.substr(start, i - start));
    start = i + 1;
    i = src.find(delimiter, i + 1);
  } while (i != std::string::npos);
  results.push_back(src.substr(start));
  return results;
}

std::vector<std::string> wrapTo(std::string src, size_t width) {
  std::vector<std::string> init_lines = split(src);
  if (width == 0) {
    return init_lines;
  }
  std::vector<std::string> wrapped_lines;
  for (const std::string& line : init_lines) {
    size_t i = 0;
    while ((i + 1) * width < line.size()) {
      wrapped_lines.push_back(line.substr(i * width, width));
      i++;
    }
    wrapped_lines.push_back(line.substr(i * width));
  }
  return wrapped_lines;
}
