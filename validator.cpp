#include "validator.h"
#include "string_utils.h"

bool RuleValidator::ValidatePortInput(const std::wstring& input, std::vector<std::pair<int, int>>& portRanges) {
    std::wstring port = input;
    std::vector<std::wstring> parts;

    // Разделяем по запятой
    size_t pos = 0;
    while ((pos = port.find(L',')) != std::wstring::npos) {
        parts.push_back(port.substr(0, pos));
        port = port.substr(pos + 1);
    }
    parts.push_back(port);

    for (const auto& part : parts) {
        // Проверяем на диапазон
        if (part.find(L'-') != std::wstring::npos) {
            size_t dashPos = part.find(L'-');
            int start = _wtoi(part.substr(0, dashPos).c_str());
            int end = _wtoi(part.substr(dashPos + 1).c_str());

            if (start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end)
                return false;

            portRanges.push_back({ start, end });
        }
        else {
            // Одиночный порт
            int singlePort = _wtoi(part.c_str());
            if (singlePort <= 0 || singlePort > 65535)
                return false;

            portRanges.push_back({ singlePort, singlePort });
        }
    }
    return true;
}

bool RuleValidator::ValidateIpInput(const std::wstring& input, std::vector<std::pair<std::string, std::string>>& ipRanges) {
    std::wstring ip = input;
    std::vector<std::wstring> parts;

    // Разделяем по запятой
    size_t pos = 0;
    while ((pos = ip.find(L',')) != std::wstring::npos) {
        parts.push_back(ip.substr(0, pos));
        ip = ip.substr(pos + 1);
    }
    parts.push_back(ip);

    for (const auto& part : parts) {
        // Проверяем на CIDR нотацию
        if (part.find(L'/') != std::wstring::npos) {
            // Реализовать проверку CIDR
            continue;
        }

        // Проверяем на диапазон
        if (part.find(L'-') != std::wstring::npos) {
            size_t dashPos = part.find(L'-');
            std::string start = WideToUtf8(part.substr(0, dashPos).c_str());
            std::string end = WideToUtf8(part.substr(dashPos + 1).c_str());

            // Здесь нужно добавить проверку корректности IP адресов
            ipRanges.push_back({ start, end });
        }
        else {
            std::string single = WideToUtf8(part.c_str());
            // Здесь нужно добавить проверку корректности IP адреса
            ipRanges.push_back({ single, single });
        }
    }
    return true;
}