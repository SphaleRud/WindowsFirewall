#pragma once
#include <vector>
#include <mutex>
#include "types.h"

class RuleManager {
private:
    // ��������� ����������� ��� ���������
    RuleManager() = default;
    ~RuleManager() = default;

    std::vector<Rule> rules;
    mutable std::mutex ruleMutex;
    int nextRuleId = 1;

public:
    // ��������� ����������� � ������������
    RuleManager(const RuleManager&) = delete;
    RuleManager& operator=(const RuleManager&) = delete;

    // ������ ���������
    static RuleManager& Instance();

    // ������ ���������� ���������
    bool AddRule(const Rule& rule);
    bool RemoveRule(int ruleId);
    bool UpdateRule(const Rule& rule);
    std::vector<Rule> GetRules() const;
    bool IsAllowed(const Connection& connection, int& matchedRuleId);
};