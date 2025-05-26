#include "validator.h"
#include "string_utils.h"
#include <sstream>
#include "resource.h"

bool RuleValidator::ValidatePortInput(const std::wstring& input, std::vector<std::pair<int, int>>& portRanges) {
    std::wstring port = input;
    std::vector<std::wstring> parts;

    // ��������� �� �������
    size_t pos = 0;
    while ((pos = port.find(L',')) != std::wstring::npos) {
        parts.push_back(port.substr(0, pos));
        port = port.substr(pos + 1);
    }
    parts.push_back(port);

    for (const auto& part : parts) {
        // ��������� �� ��������
        if (part.find(L'-') != std::wstring::npos) {
            size_t dashPos = part.find(L'-');
            int start = _wtoi(part.substr(0, dashPos).c_str());
            int end = _wtoi(part.substr(dashPos + 1).c_str());

            if (start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end)
                return false;

            portRanges.push_back({ start, end });
        }
        else {
            // ��������� ����
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

    // ��������� �� �������
    size_t pos = 0;
    while ((pos = ip.find(L',')) != std::wstring::npos) {
        parts.push_back(ip.substr(0, pos));
        ip = ip.substr(pos + 1);
    }
    parts.push_back(ip);

    for (const auto& part : parts) {
        // ��������� �� CIDR �������
        if (part.find(L'/') != std::wstring::npos) {
            // TODO: ����������� �������� CIDR
            size_t slashPos = part.find(L'/');
            std::string ipAddr = WideToUtf8(part.substr(0, slashPos).c_str());
            // �������� ����� �������
            int prefixLen = _wtoi(part.substr(slashPos + 1).c_str());
            if (prefixLen < 0 || prefixLen > 32) {
                return false;
            }
            ipRanges.push_back({ ipAddr, ipAddr }); // �������� ��������� ��� ��������� IP
            continue;
        }

        // ��������� �� ��������
        if (part.find(L'-') != std::wstring::npos) {
            size_t dashPos = part.find(L'-');
            std::string start = WideToUtf8(part.substr(0, dashPos).c_str());
            std::string end = WideToUtf8(part.substr(dashPos + 1).c_str());

            // ��������� ������� ��������� IP �������
            if (!ValidateIpAddress(start) || !ValidateIpAddress(end)) {
                return false;
            }

            ipRanges.push_back({ start, end });
        }
        else {
            std::string single = WideToUtf8(part.c_str());
            // ��������� ������������ ���������� IP ������
            if (!ValidateIpAddress(single)) {
                return false;
            }
            ipRanges.push_back({ single, single });
        }
    }
    return true;
}

// ������� ��������������� ������� ��� �������� ������������ IP ������
bool RuleValidator::ValidateIpAddress(const std::string& ip) {
    std::istringstream iss(ip);
    std::string octet;
    int count = 0;
    int value;

    while (std::getline(iss, octet, '.')) {
        count++;

        // ���������, ��� � ������ ������ �����
        if (octet.empty() || octet.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }

        // ����������� ����� � �����
        try {
            value = std::stoi(octet);
        }
        catch (...) {
            return false;
        }

        // ��������� �������� ��������
        if (value < 0 || value > 255) {
            return false;
        }

        // ��������� ������� ����
        if (octet.length() > 1 && octet[0] == '0') {
            return false;
        }
    }

    // IP ����� ������ ��������� ����� 4 ������
    return count == 4;
}

bool RuleValidator::ValidateInputs(HWND hwnd, std::wstring& errorMsg) {
    wchar_t buffer[MAX_PATH];

    // �������� ��������
    GetDlgItemText(hwnd, IDC_EDIT_NAME, buffer, MAX_PATH);
    if (wcslen(buffer) == 0) {
        errorMsg = L"������� �������� �������";
        return false;
    }

    // �������� ���������
    GetDlgItemText(hwnd, IDC_EDIT_PROGRAM, buffer, MAX_PATH);
    if (wcslen(buffer) > 0) {
        if (GetFileAttributes(buffer) == INVALID_FILE_ATTRIBUTES) {
            errorMsg = L"��������� ���� ��������� �� ����������";
            return false;
        }
    }

    // �������� IP �������
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_IP) != BST_CHECKED) {
        GetDlgItemText(hwnd, IDC_EDIT_LOCAL_IP, buffer, MAX_PATH);
        std::vector<std::pair<std::string, std::string>> ipRanges;
        if (!RuleValidator::ValidateIpInput(std::wstring(buffer), ipRanges)) {
            errorMsg = L"�������� ������ ���������� IP ������";
            return false;
        }
    }

    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_IP) != BST_CHECKED) {
        GetDlgItemText(hwnd, IDC_EDIT_REMOTE_IP, buffer, MAX_PATH);
        std::vector<std::pair<std::string, std::string>> ipRanges;
        if (!RuleValidator::ValidateIpInput(std::wstring(buffer), ipRanges)) {
            errorMsg = L"�������� ������ ���������� IP ������";
            return false;
        }
    }

    // �������� ������
    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_LOCAL_PORT) != BST_CHECKED) {
        GetDlgItemText(hwnd, IDC_EDIT_LOCAL_PORT, buffer, MAX_PATH);
        std::vector<std::pair<int, int>> portRanges;
        if (!RuleValidator::ValidatePortInput(std::wstring(buffer), portRanges)) {
            errorMsg = L"�������� ������ ���������� �����";
            return false;
        }
    }

    if (IsDlgButtonChecked(hwnd, IDC_CHECK_ANY_REMOTE_PORT) != BST_CHECKED) {
        GetDlgItemText(hwnd, IDC_EDIT_REMOTE_PORT, buffer, MAX_PATH);
        std::vector<std::pair<int, int>> portRanges;
        if (!RuleValidator::ValidatePortInput(std::wstring(buffer), portRanges)) {
            errorMsg = L"�������� ������ ���������� �����";
            return false;
        }
    }

    return true;
}