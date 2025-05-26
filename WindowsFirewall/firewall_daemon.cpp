#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include "rule_manager.h"
#include "wfp_manager.h"

const wchar_t* RULES_FILE = L"rules.json";
const int CHECK_INTERVAL_SECONDS = 10;

int main() {
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\WindowsFirewallDaemon");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "Daemon already running.\n";
        return 1;
    }

    RuleManager& ruleManager = RuleManager::Instance();
    WfpFilterManager wfpManager;
    if (!wfpManager.Initialize()) {
        std::cerr << "WFP initialization failed!\n";
        return 1;
    }

    std::cout << "Firewall daemon started, using WFP.\n";

    while (true) {
        ruleManager.LoadRulesFromFile(RULES_FILE);
        wfpManager.ApplyRules(ruleManager.GetRules());
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_INTERVAL_SECONDS));
    }

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return 0;
}