#pragma once
#include <vector>
#include <mutex>
#include <optional>
#include "types.h"

class RuleManager {
private:
    RuleManager() = default;
    ~RuleManager() = default;

    std::vector<Rule> rules;
    mutable std::mutex ruleMutex;
    int nextRuleId = 1;

public:
    RuleManager(const RuleManager&) = delete;
    RuleManager& operator=(const RuleManager&) = delete;

    static RuleManager& Instance();

    // ������� CRUD
    bool AddRule(const Rule& rule);
    bool RemoveRule(int ruleId);
    bool UpdateRule(const Rule& rule);
    std::vector<Rule> GetRules() const;
    void ShowRulesDialog(HWND hParent);

    static INT_PTR CALLBACK RulesDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // �������� rule �� id (��� UI ��������������)
    std::optional<Rule> GetRuleById(int ruleId) const;

    // �������� ���������� �� ��������
    bool IsAllowed(const Connection& connection, int& matchedRuleId);

    // �������� ��� �������
    void Clear();

    // (�����������) ������/������� (���������� �����)
    // bool LoadRulesFromFile(const std::string& filename);
    // bool SaveRulesToFile(const std::string& filename);

    // ����� nextRuleId (��� ������� ������)
    void ResetRuleIdCounter(int newNextId = 1);
};