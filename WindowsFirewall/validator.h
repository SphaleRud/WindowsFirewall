#pragma once
#include <string>
#include <vector>
#include <utility>
#include <windows.h>

class RuleValidator {
public:
    static bool ValidatePortInput(const std::wstring& input, std::vector<std::pair<int, int>>& portRanges);
    static bool ValidateIpInput(const std::wstring& input, std::vector<std::pair<std::string, std::string>>& ipRanges);
    static bool ValidateInputs(HWND hwnd, std::wstring& errorMsg);
    static bool ValidateCurrentPage(HWND hwnd);

private:
    static bool ValidateIpAddress(const std::string& ip);
};