#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <atomic>
#include "rule_manager.h"
#include "wfp_manager.h"

#define CHECK_INTERVAL_MILLISECONDS 500

const wchar_t* RULES_FILE = L"rules.json";
const int CHECK_INTERVAL_SECONDS = 10;

inline const char* ActToString(RuleAction action) {
    switch (action) {
    case RuleAction::BLOCK: return "BLOCK";
    case RuleAction::ALLOW: return "ALLOW";
    default: return "UNKNOWN";
    }
}

inline const char* ProtoToString(Protocol proto) {
    switch (proto) {
    case Protocol::ANY: return "ANY";
    case Protocol::TCP: return "TCP";
    case Protocol::UDP: return "UDP";
    case Protocol::ICMP: return "ICMP";
    default: return "UNKNOWN";
    }
}

inline const char* DirToString(RuleDirection dir) {
    switch (dir) {
    case RuleDirection::Inbound:  return "Inbound";
    case RuleDirection::Outbound: return "Outbound";
    default: return "UNKNOWN";
    }
}

void PrintActiveRules(const std::vector<Rule>& rules) {
    std::cout << "[FirewallDaemon] Active rules on start:" << std::endl;
    int idx = 1;
    for (const auto& rule : rules) {
        if (rule.enabled) {
            std::cout << idx++ << ") "
                << "ID: " << rule.id << ", "
                << "Name: " << rule.name << ", "
                << "Action: " << ActToString(rule.action) << ", "
                << "Direction: " << DirToString(rule.direction) << ", "
                << "Proto: " << ProtoToString(rule.protocol) << ", "
                << "Src: " << (rule.sourceIp.empty() ? "*" : rule.sourceIp)
                << ":" << (rule.sourcePort == 0 ? "*" : std::to_string(rule.sourcePort))
                << ", Dst: " << (rule.destIp.empty() ? "*" : rule.destIp)
                << ":" << (rule.destPort == 0 ? "*" : std::to_string(rule.destPort));
            if (!rule.appPath.empty())
                std::cout << ", App: " << rule.appPath;
            if (!rule.description.empty())
                std::cout << ", Desc: " << rule.description;
            std::cout << ", ENABLED" << std::endl;
        }
    }
    if (idx == 1)
        std::cout << "No active rules." << std::endl;
}

// ���������� ���������� ��� ���������� �����������
std::atomic<bool> g_stopFlag(false);

// ���������� ��������� �� wfpManager ��� ������� ��������
WfpFilterManager* g_wfpManager = nullptr;

// ������� ���� �������� � ���������� ������ ��� ������ ������
void RemoveAllDaemonFilters(HANDLE engineHandle, const wchar_t* filterName) {
    HANDLE enumHandle = nullptr;
    if (FwpmFilterCreateEnumHandle(engineHandle, nullptr, &enumHandle) == ERROR_SUCCESS) {
        FWPM_FILTER** filters = nullptr;
        UINT32 count = 0;
        while (FwpmFilterEnum(engineHandle, enumHandle, 100, &filters, &count) == ERROR_SUCCESS && count > 0) {
            for (UINT32 i = 0; i < count; ++i) {
                if (filters[i]->displayData.name && wcscmp(filters[i]->displayData.name, filterName) == 0) {
                    DWORD res = FwpmFilterDeleteById(engineHandle, filters[i]->filterId);
                    if (res == ERROR_SUCCESS) {
                        std::wcout << L"[WFP] (startup) Filter removed by name, id: " << filters[i]->filterId << std::endl;
                    }
                }
            }
            FwpmFreeMemory((void**)&filters);
        }
        FwpmFilterDestroyEnumHandle(engineHandle, enumHandle);
    }
}

// ���������� ���������� (Ctrl+C, �������� ����)
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    std::cout << "\n[INFO] Caught exit signal, cleaning up WFP rules...\n";
    g_stopFlag = true;
    if (g_wfpManager) {
        g_wfpManager->RemoveAllRules();
    }
    // ����� ����-����, ����� ������� ����� ������ ���������
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    return FALSE; // ��������� ����������� ���������� ��������
}

int main() {
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\WindowsFirewallDaemon");
    HANDLE hStopEvent = CreateEventW(NULL, TRUE, FALSE, L"Global\\FirewallDaemonStopEvent");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "Daemon already running.\n";
        return 1;
    }

    // ������������� ���������� ����������
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    RuleManager& ruleManager = RuleManager::Instance();
    WfpFilterManager wfpManager;
    g_wfpManager = &wfpManager;

    if (!wfpManager.Initialize()) {
        std::cerr << "WFP initialization failed!\n";
        return 1;
    }

    // �����: ������� ������ ������� � ���� ������ ��� ������
    RemoveAllDaemonFilters(wfpManager.GetEngineHandle(), L"WindowsFirewallRule"); // ������� �� �� ���, ��� � � filter.displayData.name

    std::cout << "Firewall daemon started, using WFP.\n";

    // ��������� �������
    ruleManager.LoadRulesFromFile(RULES_FILE);
    const auto& rules = ruleManager.GetRules();

    // ������� ������� ������ � �� enabled-������
    std::cout << "Rules loaded: " << rules.size() << std::endl;
    for (const auto& rule : rules) {
        std::cout << "rule.id: " << rule.id << ", enabled: " << rule.enabled << std::endl;
    }

    // >>> ����� ������� �������� ������ ��� ������
    PrintActiveRules(rules);
    wfpManager.ApplyRules(rules);

    // �������� ���� � ������������ ����������� ����������
    while (!g_stopFlag) {
        ruleManager.LoadRulesFromFile(RULES_FILE);
        wfpManager.ApplyRules(ruleManager.GetRules());
        for (int i = 0; i < CHECK_INTERVAL_SECONDS && !g_stopFlag; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        DWORD waitResult = WaitForSingleObject(hStopEvent, CHECK_INTERVAL_MILLISECONDS);
        if (waitResult == WAIT_OBJECT_0) {
            // Event ��� ������������ � ������� ���������
            break;
        }
    }

    // ��������� ������� (�� ������ ������)
    wfpManager.RemoveAllRules();
    if (g_wfpManager) {
        g_wfpManager->RemoveAllRules();
    }
    CloseHandle(hStopEvent);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    std::cout << "[INFO] Daemon exited gracefully.\n";
    return 0;
}