#pragma once
#include <vector>
#include <mutex>
#include <optional>
#include <string>
#include "rule.h"
#include "types.h"
#include <Windows.h>
#include "connection.h"
#include "firewall_logger.h"

class RuleManager {
private:
    RuleManager();
    ~RuleManager();

    std::vector<Rule> rules;
    mutable std::mutex ruleMutex;
    int nextRuleId = 1;
    RuleDirection currentDirection = RuleDirection::Inbound;
    std::string GetProtocolString(Protocol proto) const;

public:
    RuleManager(const RuleManager&) = delete;
    RuleManager& operator=(const RuleManager&) = delete;

    bool FindBlockingRule(const PacketInfo& pkt, std::string& outRuleName);

    void ApplyAllRules();

    static RuleManager& Instance();

    void SetDirection(RuleDirection direction);
    RuleDirection GetCurrentDirection() const;

    bool ShowAddRuleWizard(HWND hParent);
    bool AddRule(const Rule& rule);
    bool RemoveRule(int ruleId);
    bool UpdateRule(const Rule& rule);
    std::vector<Rule> GetRules() const;
    std::optional<Rule> GetRuleById(int ruleId) const;
    bool IsAllowed(const Connection& connection, int& matchedRuleId);
    void Clear();
    void ResetRuleIdCounter(int newNextId = 1);
    void ShowRulesDialog(HWND hParent);

    bool SaveRulesToFile(const std::wstring& path = L"rules.json") const;
    bool LoadRulesFromFile(const std::wstring& path = L"rules.json");
private:
    static INT_PTR CALLBACK RulesDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
};