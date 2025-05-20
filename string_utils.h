#pragma once
#include <string>
#include <Windows.h>

inline std::string WideToUtf8(const wchar_t* str) {
    if (!str) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, str, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return std::string();

    std::string result(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, str, -1, &result[0], size_needed, nullptr, nullptr);
    return result;
}

inline std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    if (size_needed <= 0) return std::wstring();

    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], size_needed);
    return result;
}