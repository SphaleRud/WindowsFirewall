#pragma once
#include <string>
#include <vector>
#include <utility>

class RuleValidator {
public:
    static bool ValidatePortInput(const std::wstring& input, std::vector<std::pair<int, int>>& portRanges);
    static bool ValidateIpInput(const std::wstring& input, std::vector<std::pair<std::string, std::string>>& ipRanges);
};