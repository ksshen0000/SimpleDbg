#ifndef SIMPLEDBG_SOURCE_TOOLS_H
#define SIMPLEDBG_SOURCE_TOOLS_H
#include <string>
#include <vector>
#include <cstdint>
std::string run_source_tool(const std::vector<std::string>& arguments);
std::string source_location(const std::string& object, uint64_t address);
std::vector<uint64_t> source_addresses(const std::string& object, const std::string& file, unsigned line);
#endif
