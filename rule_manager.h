#pragma once
#include <vector>
#include <mutex>
#include <optional>
#include <string>
#include "types.h"
#include <Windows.h>

class RuleManager {
private:
    RuleManager();
    ~RuleManager();

    std::vector<Rule> rules;
    mutable std::mutex ruleMutex;
    int nextRuleId = 1;

    // ����� ������ ���������� �������
    static INT_PTR CALLBACK FirewallRuleWizardProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    bool ShowAddRuleWizard(HWND hParent);

public:
    RuleManager(const RuleManager&) = delete;
    RuleManager& operator=(const RuleManager&) = delete;

    static RuleManager& Instance();

    bool AddRule(const Rule& rule);
    bool RemoveRule(int ruleId);
    bool UpdateRule(const Rule& rule);
    std::vector<Rule> GetRules() const;
    std::optional<Rule> GetRuleById(int ruleId) const;
    bool IsAllowed(const Connection& connection, int& matchedRuleId);
    void Clear();
    void ResetRuleIdCounter(int newNextId = 1);

    // �������� ���� � ���������
    void ShowRulesDialog(HWND hParent);

private:
    // ���������� ����
    static INT_PTR CALLBACK RulesDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
};

    // (�����������) ������/������� (���������� �����)
    // bool LoadRulesFromFile(const std::string& filename);
    // bool SaveRulesToFile(const std::string& filename);
